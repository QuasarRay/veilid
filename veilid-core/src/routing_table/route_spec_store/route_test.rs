use super::*;

/// Number of consecutive successful pings required to consider a route tested
const ROUTE_TEST_PING_COUNT: usize = 3;

/// Information about a route that can be used for testing
pub struct AllocatedRouteTestInfo {
    /// The best route set key
    pub key: PublicKey,
    /// The hops for the route
    pub hops: Vec<NodeRef>,
}

impl RouteSpecStore {
    /// Get the test info for an allocated route
    pub fn get_allocated_route_test_info(
        &self,
        route_id: &RouteId,
    ) -> Option<AllocatedRouteTestInfo> {
        let cache = self.cache.read();
        let arce = cache.get_allocated_route_by_id(route_id)?;
        let key = arce.best_route_set_key()?;
        let hops = arce.hop_node_refs();

        Some(AllocatedRouteTestInfo { key, hops })
    }

    /// Test an allocated route for continuity. Only used during allocation, not by keepalives.
    /// Can test remote routes but currently is not used for that.
    /// Sends ROUTE_TEST_PING_COUNT consecutive pings (3 currently) to the route to see if it is valid. The
    /// route fails to test if any of the pings fail.
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab::route", skip(self), ret, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn test_route(&self, id: RouteId) -> VeilidAPIResult<Option<bool>> {
        let is_remote = self.is_route_id_remote(&id);
        if is_remote {
            Box::pin(self.test_remote_route(id)).await
        } else {
            Box::pin(self.test_allocated_route(id)).await
        }
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab::route", skip(self), ret, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn test_allocated_route(&self, id: RouteId) -> VeilidAPIResult<Option<bool>> {
        // Make loopback route to test with
        let (dest, hops) = {
            // Get the best allocated route for this id
            let (key, hops) = {
                let cache = self.cache.read();
                let Some(arce) = cache.get_allocated_route_by_id(&id) else {
                    // Route id is already dead or missing
                    return Ok(Some(false));
                };
                let Some(key) = arce.best_route_set_key() else {
                    apibail_internal!("no best key to test allocated route");
                };
                // Get the hops so we can match the route's hop length for safety
                // route length as well as marking nodes as unreliable if this fails
                let hops = arce.hop_node_refs();
                (key, hops)
            };

            // Get the private route to send to
            let private_route = match self.assemble_single_private_route(&key, None).await {
                Ok(v) => v,
                Err(VeilidAPIError::InvalidTarget { message: _ }) => {
                    // Route missing means its dead
                    return Ok(Some(false));
                }
                Err(VeilidAPIError::TryAgain { message: _ }) => {
                    // Try again means we didn't test because we couldnt assemble
                    return Ok(None);
                }
                Err(e) => {
                    return Err(e);
                }
            };

            // Always test routes with safety routes that are more likely to succeed
            let stability = Stability::Reliable;
            // Routes should test with the most likely to succeed sequencing they are capable of
            let sequencing = Sequencing::PreferOrdered;
            // Hop count for safety spec should match the private route spec
            let hop_count = hops.len();

            let safety_spec = SafetySpec {
                preferred_route: Some(id),
                hop_count,
                stability,
                sequencing,
            };
            let safety_selection = SafetySelection::Safe(safety_spec);

            (
                Destination::PrivateRoute {
                    private_route,
                    safety_selection,
                },
                hops,
            )
        };

        // Test with multiple round-trip pings to self to ensure route reliability
        let rpc_processor = self.rpc_processor();
        for _ping in 0..ROUTE_TEST_PING_COUNT {
            let _res = match Box::pin(rpc_processor.rpc_call_status(dest.clone())).await? {
                NetworkResult::Value(v) => v,
                _ => {
                    // Did not error, but did not come back, mark the nodes as failed to send, and then return false
                    // This will prevent those node from immediately being included in the next allocated route,
                    // avoiding the same route being constructed to replace this one when it is removed.
                    for hop in hops {
                        hop.report_failed_route_test();
                    }
                    return Ok(Some(false));
                }
            };
        }

        Ok(Some(true))
    }

    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab::route", skip(self), ret, err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    async fn test_remote_route(&self, id: RouteId) -> VeilidAPIResult<Option<bool>> {
        // Make private route test
        let dest = {
            // Get the route to test
            let Some(private_route) = self.best_remote_private_route(&id) else {
                apibail_internal!("no best key to test remote route");
            };

            // Always test routes with safety routes that are more likely to succeed
            let stability = Stability::Reliable;
            // Routes should test with the most likely to succeed sequencing they are capable of
            let sequencing = Sequencing::PreferOrdered;

            // Get a safety route that is good enough
            let safety_spec = SafetySpec {
                preferred_route: None,
                hop_count: self.get_default_route_hop_count_safe(),
                stability,
                sequencing,
            };

            let safety_selection = SafetySelection::Safe(safety_spec);

            Destination::PrivateRoute {
                private_route,
                safety_selection,
            }
        };

        // Test with double-round trip ping to self
        let _res = match Box::pin(self.rpc_processor().rpc_call_status(dest)).await? {
            NetworkResult::Value(v) => v,
            _ => {
                // Did not error, but did not come back, just return false
                return Ok(Some(false));
            }
        };

        Ok(Some(true))
    }
}
