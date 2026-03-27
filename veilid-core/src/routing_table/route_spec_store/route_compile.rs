use super::*;

#[derive(Clone, Debug)]
pub struct CompileRouteParams {
    pub safety_selection: SafetySelection,
    pub private_route: Arc<PrivateRoute>,
    pub opt_reply_pr_pubkey: Option<PublicKey>, // Should be route id someday
}
// Compiled route key for caching
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompiledRouteCacheKey {
    pub safety_selection: SafetySelection,
    pub pr_pubkey: PublicKey,                   // Should be route id someday
    pub opt_reply_pr_pubkey: Option<PublicKey>, // Should be route id someday
}

impl From<&CompileRouteParams> for CompiledRouteCacheKey {
    fn from(params: &CompileRouteParams) -> Self {
        Self {
            safety_selection: params.safety_selection.clone(),
            pr_pubkey: params.private_route.public_key.clone(),
            opt_reply_pr_pubkey: params.opt_reply_pr_pubkey.clone(),
        }
    }
}

/// Compiled route (safety route + private route)
#[derive(Debug)]
pub struct CompiledRoute {
    /// The safety route attached to the private route
    pub safety_route: Arc<SafetyRoute>,
    /// The secret used to encrypt the message payload
    pub secret: SecretKey,
    /// The node ref to the first hop in the compiled route
    /// filtered to the safetyselection it was compiled with
    pub first_hop: FilteredNodeRef,
    /// Whether this compiled route was built with optimized hop encoding (NodeId only vs full PeerInfo)
    pub optimized: bool,
}

/// Internal parameters for building route hops, shared between optimized and unoptimized compilation
struct RouteCompileContext {
    /// The public key of the safety route
    sr_pubkey: PublicKey,
    /// The first hop in the compiled route filtered to the safety selection it was compiled with
    first_hop: FilteredNodeRef,
    /// The secret for the safety route
    secret: SecretKey,
    /// The node refs of the hops in the safety route
    hop_node_refs: Vec<NodeRef>,
    /// Whether this compiled route can be built with optimized hop encoding (NodeId only vs full PeerInfo)
    optimize: bool,
}

impl RouteSpecStore {
    /// Extracts the compile context from route spec details for a resolved safety route.
    fn get_route_compile_context(
        &self,
        safety_route_id: &RouteId,
        sr_pubkey: PublicKey,
        safety_spec: &SafetySpec,
    ) -> VeilidAPIResult<RouteCompileContext> {
        let cache = self.cache.read();

        let Some(safety_arce) = cache.get_allocated_route_by_id(safety_route_id) else {
            apibail_internal!("safety route not in cache");
        };

        // Get the first hop noderef of the safety route
        let first_hop = safety_arce.hop_node_ref(0).unwrap_or_log();

        // Ensure sequencing requirement is set on first hop
        let mut first_hop = first_hop.sequencing_filtered(safety_spec.sequencing);

        // Enforce the routing domain
        first_hop
            .merge_filter(NodeRefFilter::new().with_routing_domain(RoutingDomain::PublicInternet));

        let secret = safety_arce.route_set_secret_for_key(&sr_pubkey)?;

        let optimize = safety_arce.with_stats(|stats| stats.last_known_valid_ts.is_some());

        let hop_node_refs = safety_arce.hop_node_refs();

        Ok(RouteCompileContext {
            sr_pubkey,
            first_hop,
            secret,
            hop_node_refs,
            optimize,
        })
    }

    /// Build the encrypted hop chain
    async fn compile_route_inner(
        routing_table: &RoutingTable,
        params: &CompileRouteParams,
        ctx: RouteCompileContext,
    ) -> VeilidAPIResult<Arc<CompiledRoute>> {
        let crypto_kind = params.private_route.crypto_kind();
        let crypto = routing_table.crypto();
        let Some(vcrypto) = crypto.get_async(crypto_kind) else {
            apibail_generic!("crypto not supported for route");
        };

        // start last blob-to-encrypt data off as private route
        let mut blob_data = {
            let mut pr_message = ::capnp::message::Builder::new_default();
            let mut pr_builder = pr_message.init_root::<veilid_capnp::private_route::Builder>();
            encode_private_route(&params.private_route, &mut pr_builder)?;
            let mut blob_data =
                canonical_message_builder_to_bytes_writer_packed(pr_message, |size| {
                    BytesWriter::with_capacity(size + 1 + vcrypto.aead_overhead())
                })?
                .into_inner();

            // append the private route tag so we know how to decode it later
            blob_data.extend_from_slice(&[1u8]);
            blob_data
        };

        // Encode each hop from inside to outside
        // skips the outermost hop since that's entering the
        // safety route and does not include the dialInfo
        // (outer hop is a RouteHopData, not a RouteHop).
        // Each loop mutates 'nonce', and 'blob_data'
        let mut nonce = vcrypto.random_nonce().await;

        let mut hop_info = Vec::with_capacity(ctx.hop_node_refs.len() - 1);
        let first_hop_public_key = {
            // Forward order (safety route), but inside-out
            for h in (1..ctx.hop_node_refs.len()).rev() {
                let hop_node_ref = &ctx.hop_node_refs[h];
                let (hop_node_id, hop_public_key, hop_peer_info) = {
                    hop_node_ref.operate(|e| {
                        let Some(hop_node_id) = e.node_ids().get(crypto_kind) else {
                            apibail_invalid_argument!(
                                "no hop node id for route hop",
                                "crypto_kind",
                                crypto_kind
                            );
                        };
                        let Some(hop_public_key) = e
                            .public_keys(RoutingDomain::PublicInternet)
                            .get(crypto_kind)
                        else {
                            apibail_invalid_argument!(
                                "no hop public key for route hop",
                                "crypto_kind",
                                crypto_kind
                            );
                        };
                        let Some(hop_peer_info) = e.get_peer_info(RoutingDomain::PublicInternet)
                        else {
                            apibail_invalid_argument!(
                                "no hop peer info for route hop",
                                "crypto_kind",
                                crypto_kind
                            );
                        };
                        Ok((hop_node_id, hop_public_key, hop_peer_info))
                    })?
                };

                hop_info.push((hop_node_id, hop_public_key, hop_peer_info));
            }

            let first_hop_node_ref = &ctx.hop_node_refs[0];
            let Some(first_hop_public_key) = first_hop_node_ref
                .public_keys(RoutingDomain::PublicInternet)
                .get(crypto_kind)
            else {
                apibail_invalid_argument!(
                    "no hop public key for route hop",
                    "crypto_kind",
                    crypto_kind
                );
            };
            first_hop_public_key
        };

        for (hop_node_id, hop_public_key, hop_peer_info) in hop_info {
            // Get blob to encrypt for next hop
            blob_data = {
                // Encrypt the previous blob ENC(nonce, DH(PKhop,SKsr))
                let dh_secret = vcrypto
                    .cached_dh(&hop_public_key, &ctx.secret)
                    .await
                    .map_err(VeilidAPIError::internal)?;
                let enc_blob_data = vcrypto
                    .encrypt_in_place_aead(blob_data, &nonce, &dh_secret, None)
                    .await
                    .map_err(VeilidAPIError::internal)?;

                // Make route hop data
                let route_hop_data = RouteHopData {
                    nonce,
                    blob: enc_blob_data.freeze(),
                };

                // Make route hop
                let route_hop = RouteHop {
                    node: if ctx.optimize {
                        // Optimized, no peer info, just the dht key
                        RouteNode::NodeId(hop_node_id)
                    } else {
                        // Full peer info, required until we are sure the route has been fully established
                        RouteNode::PeerInfo(hop_peer_info)
                    },
                    next_hop: Some(route_hop_data),
                };

                // Make next blob from route hop
                let mut rh_message = ::capnp::message::Builder::new_default();
                let mut rh_builder = rh_message.init_root::<veilid_capnp::route_hop::Builder>();
                encode_route_hop(&route_hop, &mut rh_builder)?;
                let mut blob_data =
                    canonical_message_builder_to_bytes_writer_packed(rh_message, |size| {
                        BytesWriter::with_capacity(size + 1 + vcrypto.aead_overhead())
                    })?
                    .into_inner();

                // Append the route hop tag so we know how to decode it later
                blob_data.extend_from_slice(&[0u8]);
                blob_data
            };

            // Make another nonce for the next hop
            nonce = vcrypto.random_nonce().await;
        }

        // Encode first RouteHopData
        let dh_secret = vcrypto
            .cached_dh(&first_hop_public_key, &ctx.secret)
            .await
            .map_err(VeilidAPIError::internal)?;
        let enc_blob_data = vcrypto
            .encrypt_in_place_aead(blob_data, &nonce, &dh_secret, None)
            .await
            .map_err(VeilidAPIError::internal)?;

        let route_hop_data = RouteHopData {
            nonce,
            blob: enc_blob_data.freeze(),
        };

        let hops = SafetyRouteHops::Data(route_hop_data);

        Ok(Arc::new(CompiledRoute {
            safety_route: Arc::new(SafetyRoute {
                public_key: ctx.sr_pubkey,
                hops,
            }),
            secret: ctx.secret,
            first_hop: ctx.first_hop,
            optimized: ctx.optimize,
        }))
    }

    /// Compiles a safety route to the private route, with caching
    ///
    /// Both optimized and unoptimized routes are cached. When a cached unoptimized
    /// route is found and the safety route has since been validated, the cache entry
    /// is evicted and the route is recompiled as optimized. This ensures that the
    /// same safety route is reused (pinned) across calls while still upgrading to
    /// optimized encoding once the route is proven valid.
    ///
    /// Parameters:
    ///   * safety_selection - The safety selection to use
    ///   * private_route - The private route we are sending to
    ///   * reply_private_route - The private route we want the response to go to, if None, we will se a new safety route
    ///
    /// Returns:
    ///   * Err(VeilidAPIError::TryAgain) if no allocation could happen at this time (not an error)
    ///   * Other Err() if the parameters are wrong
    ///   * Ok(compiled route) on success
    #[cfg_attr(
        feature = "instrument",
        instrument(level = "trace", target = "rtab::route", skip_all, fields(__VEILID_LOG_KEY = self.log_key()))
    )]
    pub async fn compile_route(
        &self,
        params: &CompileRouteParams,
    ) -> VeilidAPIResult<Arc<CompiledRoute>> {
        #[cfg(feature = "verbose-tracing")]
        let profile_start_ts = Timestamp::now();
        let compiled_route_cache_key: CompiledRouteCacheKey = params.into();

        let opt_compile_lock = {
            let cache = self.cache.read();
            if let Some(compiled_route) =
                cache.lookup_compiled_route_cache(&compiled_route_cache_key)
            {
                #[cfg(feature = "verbose-tracing")]
                veilid_log!(self trace "compile_route profile (fast path cached): {:#}", Timestamp::now().duration_since(profile_start_ts));
                return Ok(compiled_route);
            }
            self.compile_lock_table
                .try_lock_tag(compiled_route_cache_key.clone())
        };

        // Get the compile lock to ensure we only do this for a particular private route one at at time
        let compile_lock = if let Some(compile_lock) = opt_compile_lock {
            // Fast path, we have a compile lock
            compile_lock
        } else {
            // Slow path, we have to get a compile lock and account for race conditions on route cache
            let compile_lock = self
                .compile_lock_table
                .lock_tag(compiled_route_cache_key.clone())
                .measure_debug(
                    TimestampDuration::new_ms(1),
                    veilid_log_dbg!(self, "compile_lock"),
                )
                .await;

            // Check again due to race condition on route cache
            let cache = self.cache.read();
            if let Some(compiled_route) =
                cache.lookup_compiled_route_cache(&compiled_route_cache_key)
            {
                #[cfg(feature = "verbose-tracing")]
                veilid_log!(self debug "compile_route profile (slow path cached): {:#}", Timestamp::now().duration_since(profile_start_ts));
                return Ok(compiled_route);
            }

            compile_lock
        };

        let routing_table = self.routing_table();

        // Get useful private route properties
        let crypto_kind = params.private_route.crypto_kind();
        let pr_pubkey = params.private_route.public_key.clone();

        // See if we are using a safety route, if not, short circuit this operation
        let safety_spec = match &params.safety_selection {
            // Safety route spec to use
            SafetySelection::Safe(safety_spec) => safety_spec,
            // Safety route stub with the node's public key as the safety route key since it's the 0th hop
            SafetySelection::Unsafe(sequencing) => {
                let (opt_pr_first_hop_node, private_route) = params.private_route.split_first_hop();
                let Some(pr_first_hop_node) = opt_pr_first_hop_node else {
                    apibail_generic!("compiled private route should have first hop");
                };

                let opt_first_hop = match pr_first_hop_node {
                    RouteNode::NodeId(id) => routing_table
                        .lookup_node_id(id)
                        .map_err(VeilidAPIError::internal)?,
                    RouteNode::PeerInfo(pi) => Some(
                        routing_table
                            .register_node_with_peer_info(pi, false)
                            .map_err(VeilidAPIError::internal)?
                            .unfiltered(),
                    ),
                };
                let Some(first_hop) = opt_first_hop else {
                    // Can't reach this private route any more
                    apibail_generic!("can't reach private route any more");
                };

                // Set sequencing requirement
                let mut first_hop = first_hop.sequencing_filtered(*sequencing);

                // Enforce the routing domain
                first_hop.merge_filter(
                    NodeRefFilter::new().with_routing_domain(RoutingDomain::PublicInternet),
                );

                // Return the compiled safety route
                let stub_compiled_route = Arc::new(CompiledRoute {
                    safety_route: Arc::new(SafetyRoute::new_stub(
                        routing_table.public_key(crypto_kind),
                        Arc::new(private_route),
                    )),
                    secret: routing_table.secret_key(crypto_kind),
                    first_hop,
                    optimized: true, // Stubs are always considered optimized
                });

                // Cache the compiled route stub
                self.cache.read().add_to_compiled_route_cache(
                    compiled_route_cache_key,
                    stub_compiled_route.clone(),
                )?;

                #[cfg(feature = "verbose-tracing")]
                veilid_log!(self debug "compile_route profile (stub): {:#}", Timestamp::now().duration_since(profile_start_ts));
                return Ok(stub_compiled_route);
            }
        };

        // If the safety route requested is also the private route, this is a loopback test, just accept it
        let opt_safety_route_id_and_public_key = {
            let cache = self.cache.read();
            let opt_private_route_id = cache.get_allocated_route_id_by_key(&pr_pubkey);

            if safety_spec.preferred_route.is_some()
                && safety_spec.preferred_route == opt_private_route_id
            {
                // Private route is also safety route during loopback test
                Some((opt_private_route_id.unwrap(), pr_pubkey.clone()))
            } else {
                match params.opt_reply_pr_pubkey.as_ref() {
                    Some(pr_public_key) => {
                        // Symmetric routing: Use the reply private route as the safety route
                        // XXX: add a safety selection switch to use asymmetric routes
                        let Some(reply_private_route_id) =
                            cache.get_allocated_route_id_by_key(pr_public_key)
                        else {
                            apibail_generic!("safety route id missing");
                        };
                        Some((reply_private_route_id, pr_public_key.clone()))
                    }
                    None => {
                        // Reply route not specified, choose a safety route
                        None
                    }
                }
            }
        };

        let (safety_route_id, sr_pubkey) =
            if let Some(safety_route_id_and_public_key) = opt_safety_route_id_and_public_key {
                safety_route_id_and_public_key
            } else {
                let Some(avoid_node_id) = params.private_route.first_hop_node_id() else {
                    apibail_generic!("compiled private route should have first hop");
                };
                let select_params = RouteSelectParams {
                    crypto_kind,
                    preferred_route: safety_spec.preferred_route.clone(),
                    hop_count: safety_spec.hop_count,
                    stability: safety_spec.stability,
                    sequencing: safety_spec.sequencing,
                    directions: Direction::Out.into(),
                    avoid_nodes: vec![avoid_node_id],
                    is_destination_safe: !params.private_route.is_stub(),
                };

                let RouteIdAndKeys {
                    route_id,
                    route_set_keys: public_keys,
                } = self.select_single_route(select_params).await?;
                (route_id, public_keys.get(crypto_kind).unwrap())
            };

        // Get the compile context (shared state for both optimized and unoptimized paths)
        let ctx = self.get_route_compile_context(&safety_route_id, sr_pubkey, safety_spec)?;

        #[cfg(feature = "verbose-tracing")]
        let optimize = ctx.optimize;

        // Compile using the appropriate method
        let compiled_route = Self::compile_route_inner(&routing_table, params, ctx).await?;

        // Always cache the compiled route (both optimized and unoptimized)
        // Unoptimized routes are cached to pin the safety route selection,
        // and will be upgraded to optimized on cache hit once validated
        self.cache
            .read()
            .add_to_compiled_route_cache(compiled_route_cache_key, compiled_route.clone())?;

        // Release compile lock (doing this explicitly here for clarity)
        drop(compile_lock);

        // Return compiled route
        #[cfg(feature = "verbose-tracing")]
        veilid_log!(self debug "compile_route profile (uncached{}): {:#}", if optimize { "" } else { " unoptimized" }, Timestamp::now().duration_since(profile_start_ts));

        Ok(compiled_route)
    }
}
