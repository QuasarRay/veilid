use super::*;

impl_veilid_log_facility!("rtab");

/// Number of automatic safety routes of each safe/unsafe default length to maintain
const DESIRED_BACKGROUND_SAFETY_ROUTE_COUNT: usize = 4;
/// Number of automatic safety routes of each safe/unsafe default length required for operation
const MINIMUM_BACKGROUND_SAFETY_ROUTE_COUNT: usize = 2;

impl PublicInternetRoutingDomainController {
    /// Fastest routes sort
    fn route_sort_latency_fn(a: &(RouteId, u64), b: &(RouteId, u64)) -> cmp::Ordering {
        let mut al = a.1;
        let mut bl = b.1;
        // Treat zero latency as uncalculated
        if al == 0 {
            al = u64::MAX;
        }
        if bl == 0 {
            bl = u64::MAX;
        }
        // Less is better
        let c = al.cmp(&bl);
        if c != cmp::Ordering::Equal {
            return c;
        }

        // Otherwise, just sort by route id
        a.0.cmp(&b.0)
    }

    /// Determine if we have enough safety routes that have been -tested- allocated to perform routing operations
    pub(in crate::routing_table) fn safety_routes_ready(&self) -> bool {
        let routing_table = self.routing_table();
        let rss = routing_table.route_spec_store();

        let mut safe_route_count = 0;
        let mut unsafe_route_count = 0;

        rss.list_allocated_routes(|_k, v| {
            let is_known_valid = v.with_stats(|stats| stats.last_known_valid_ts.is_some());
            if is_known_valid && v.is_automatic() {
                if v.hop_count() == rss.get_default_route_hop_count_safe() {
                    safe_route_count += 1;
                } else if v.hop_count() == rss.get_default_route_hop_count_unsafe() {
                    unsafe_route_count += 1;
                }
            }
            Option::<()>::None
        });

        safe_route_count >= MINIMUM_BACKGROUND_SAFETY_ROUTE_COUNT
            && unsafe_route_count >= MINIMUM_BACKGROUND_SAFETY_ROUTE_COUNT
    }

    /// Get the list of routes to test and drop
    ///
    /// Allocated routes to test:
    /// * if a route 'needs_testing'
    ///   . all published allocated routes
    ///   . routes that have never been tested
    ///   . the fastest 0..N automatic safety routes of safe default length
    ///   . the fastest 0..N automatic safety routes of unsafe default length
    ///
    /// Routes to drop:
    /// * if a route 'needs_testing'
    ///   . the remaining automatic safety routes
    ///   . the rest of the allocated unpublished routes
    ///
    /// If a route doesn't 'need_testing', then we neither test nor drop it
    #[cfg_attr(feature = "instrument", instrument(level = "trace", skip(self), ret, fields(__VEILID_LOG_KEY = self.log_key())))]
    fn get_allocated_routes_to_test(&self, cur_ts: Timestamp) -> Vec<RouteId> {
        let routing_table = self.routing_table();
        let rss = routing_table.route_spec_store();
        let default_route_hop_count_safe = rss.get_default_route_hop_count_safe();
        let default_route_hop_count_unsafe = rss.get_default_route_hop_count_unsafe();

        let mut must_test_routes = Vec::<RouteId>::new();
        let mut automatic_safe_routes = Vec::<(RouteId, u64)>::new();
        let mut automatic_unsafe_routes = Vec::<(RouteId, u64)>::new();
        let mut expired_routes = Vec::<RouteId>::new();
        rss.list_allocated_routes(|k, v| {
            v.with_stats(|stats| {
                // Ignore routes that don't need or want testing
                if !stats.needs_testing(cur_ts) {
                    return Option::<()>::None;
                }
                // If this has been published, always test if we need it
                // Also if the route has never been tested, test it at least once
                if v.is_published() || stats.last_known_valid_ts.is_none() {
                    must_test_routes.push(k.clone());
                }
                // If this is of default safe route hop length, include it in routes to keep alive
                else if v.is_automatic() && v.hop_count() == default_route_hop_count_safe {
                    automatic_safe_routes.push((k.clone(), stats.latency.average.as_u64()));
                }
                // If this is a default unsafe route hop length, include it in routes to keep alive
                else if v.is_automatic() && v.hop_count() == default_route_hop_count_unsafe {
                    automatic_unsafe_routes.push((k.clone(), stats.latency.average.as_u64()));
                }
                // Else this is a route that hasnt been used recently enough and we can tear it down
                else {
                    expired_routes.push(k.clone());
                }
                Option::<()>::None
            })
        });

        // Sort automatic routes by speed if we know the speed
        automatic_safe_routes.sort_by(Self::route_sort_latency_fn);
        automatic_unsafe_routes.sort_by(Self::route_sort_latency_fn);

        // Save up to N unpublished routes and test them
        let background_safety_route_count = DESIRED_BACKGROUND_SAFETY_ROUTE_COUNT;

        let safe_routes_to_keep =
            usize::min(background_safety_route_count, automatic_safe_routes.len());
        for automatic_safe_route in automatic_safe_routes.iter().take(safe_routes_to_keep) {
            must_test_routes.push(automatic_safe_route.0.clone());
        }
        let unsafe_routes_to_keep =
            usize::min(background_safety_route_count, automatic_unsafe_routes.len());
        for automatic_unsafe_route in automatic_unsafe_routes.iter().take(unsafe_routes_to_keep) {
            must_test_routes.push(automatic_unsafe_route.0.clone());
        }

        // Kill off all but N unpublished routes rather than testing them
        if automatic_safe_routes.len() > safe_routes_to_keep {
            for x in &automatic_safe_routes[safe_routes_to_keep..] {
                expired_routes.push(x.0.clone());
            }
        }
        if automatic_unsafe_routes.len() > unsafe_routes_to_keep {
            for x in &automatic_unsafe_routes[unsafe_routes_to_keep..] {
                expired_routes.push(x.0.clone());
            }
        }

        // Process dead routes
        for r in expired_routes {
            veilid_log!(self debug "Expired route: {}", r);
            rss.release_route(r);
        }

        // return routes to test
        must_test_routes
    }

    /// Keep private routes assigned and accessible
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", skip(self, _stop_token), err, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn private_route_management_task_routine(
        &self,
        _stop_token: StopToken,
        _last_ts: Timestamp,
        cur_ts: Timestamp,
    ) -> EyreResult<()> {
        let routing_table = self.routing_table();
        let rss = routing_table.route_spec_store();

        // Get locally allocated routes needing testing and enqueue them
        let routes_needing_testing = self.get_allocated_routes_to_test(cur_ts);
        if !routes_needing_testing.is_empty() {
            veilid_log!(self debug "Enqueuing {} allocated route tests", routes_needing_testing.len());
            routing_table
                .enqueue_route_tests(routes_needing_testing, 0)
                .await;
        }

        // Ensure we have a minimum of N allocated local, unpublished routes with the default number of hops
        // and all our supported crypto kinds. Also allocate some routes of twice the default length for
        // safety routes to direct nodes.
        let default_route_hop_count_safe = rss.get_default_route_hop_count_safe();
        let default_route_hop_count_unsafe = rss.get_default_route_hop_count_unsafe();

        let mut local_safety_route_count_safe = 0usize;
        let mut local_safety_route_count_unsafe = 0usize;

        rss.list_allocated_routes(|_k, v| {
            if !v.is_published() && v.is_automatic() {
                if v.hop_count() == default_route_hop_count_safe {
                    local_safety_route_count_safe += 1;
                } else if v.hop_count() == default_route_hop_count_unsafe {
                    local_safety_route_count_unsafe += 1;
                }
            }
            Option::<()>::None
        });

        let background_safety_route_count = DESIRED_BACKGROUND_SAFETY_ROUTE_COUNT;

        // Newly allocated routes, separated by type for interleaving
        let mut newly_safe_routes = Vec::new();
        let mut newly_unsafe_routes = Vec::new();

        // Allocate more routes if needed
        for (route_count, hop_count, is_safe) in [
            (
                local_safety_route_count_safe,
                default_route_hop_count_safe,
                true,
            ),
            (
                local_safety_route_count_unsafe,
                default_route_hop_count_unsafe,
                false,
            ),
        ] {
            if route_count < background_safety_route_count {
                let routes_to_allocate = background_safety_route_count - route_count;

                // Parameters here must be the most inclusive route allocation spec
                // These will be used by test_remote_route as well
                let params = AllocateRouteParams {
                    crypto_kinds: VALID_CRYPTO_KINDS.to_vec(),
                    hop_count,
                    stability: Stability::Reliable,
                    sequencing: Sequencing::PreferOrdered,
                    directions: DirectionSet::all(),
                    avoid_nodes: Vec::new(),
                    automatic: true,
                };
                for _n in 0..routes_to_allocate {
                    match rss.allocate_route(params.clone()).await {
                        Err(VeilidAPIError::TryAgain { message }) => {
                            veilid_log!(self debug "Route allocation unavailable: {}", message);
                        }
                        Err(e) => return Err(e.into()),
                        Ok(v) => {
                            if is_safe {
                                newly_safe_routes.push(v.route_id);
                            } else {
                                newly_unsafe_routes.push(v.route_id);
                            }
                        }
                    }
                }
            }
        }

        // Interleave safe and unsafe routes so the first batch of parallel tests
        // includes both types. This ensures safety_routes_ready() sees both safe=1+
        // and unsafe=1+ after the first batch completes, rather than having to wait
        // for all safe routes to finish before any unsafe routes start.
        let mut newly_allocated_routes = Vec::new();
        let max_len = newly_safe_routes.len().max(newly_unsafe_routes.len());
        for i in 0..max_len {
            if let Some(r) = newly_safe_routes.get(i) {
                newly_allocated_routes.push(r.clone());
            }
            if let Some(r) = newly_unsafe_routes.get(i) {
                newly_allocated_routes.push(r.clone());
            }
        }

        // Enqueue tests for newly allocated routes
        if !newly_allocated_routes.is_empty() {
            veilid_log!(self debug "Enqueuing {} newly allocated route tests ({} safe, {} unsafe)",
                newly_allocated_routes.len(), newly_safe_routes.len(), newly_unsafe_routes.len());
            routing_table
                .enqueue_route_tests(newly_allocated_routes, 0)
                .await;
        }

        // Enqueue remote route tests at slightly lower priority
        let remote_routes_needing_testing = rss.list_remote_routes(|k, v| {
            v.with_stats(|stats| {
                if stats.needs_testing(cur_ts) {
                    Some(k.clone())
                } else {
                    None
                }
            })
        });
        if !remote_routes_needing_testing.is_empty() {
            veilid_log!(self debug "Enqueuing {} remote route tests", remote_routes_needing_testing.len());
            routing_table
                .enqueue_route_tests(remote_routes_needing_testing, 10)
                .await;
        }

        // Send update (also may send updates for released routes done by other parts of the program)
        rss.send_route_update();

        Ok(())
    }
}
