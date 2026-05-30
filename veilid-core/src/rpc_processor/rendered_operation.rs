use super::*;

/// An operation that has been fully prepared for envelope
pub struct RenderedOperation {
    /// The rendered operation id for logging purposes,
    /// which may be different from the message's op_id
    /// if it wrapped with a route
    pub outer_op_id: OperationId,
    /// The rendered signed operation bytes
    pub message: Bytes,
    /// Node to send to
    pub node_ref: FilteredNodeRef,
    /// Optional relay dialinfo to send directly to
    pub opt_relay_di: Option<DialInfo>,
    /// The safety route used to send the message (held for the operation's lifetime)
    pub opt_safety_route_ref: Option<AllocatedRouteRef>,
    /// The remote private route used to send the message (held for the operation's lifetime)
    pub opt_remote_private_route_ref: Option<RemoteRouteRef>,
    /// The private route requested to receive the reply (held for the operation's lifetime)
    pub opt_reply_private_route_ref: Option<AllocatedRouteRef>,
}

impl fmt::Debug for RenderedOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderedOperation")
            .field("outer_op_id", &self.outer_op_id)
            .field("message(len)", &self.message.len())
            .field("node_ref", &self.node_ref)
            .field("opt_relay_di", &self.opt_relay_di)
            .field("opt_safety_route_ref", &self.opt_safety_route_ref)
            .field(
                "opt_remote_private_route_ref",
                &self.opt_remote_private_route_ref,
            )
            .field(
                "opt_reply_private_route_ref",
                &self.opt_reply_private_route_ref,
            )
            .finish()
    }
}
