use super::*;
use core::convert::TryInto;

fn reject_unspecified_socket_address(socket_address: &SocketAddress) -> Result<(), RPCError> {
    if socket_address.address().is_unspecified() {
        return Err(RPCError::protocol(
            "dial info with unspecified (0.0.0.0 or ::) address not allowed",
        ));
    }
    Ok(())
}

pub fn decode_dial_info(reader: &veilid_capnp::dial_info::Reader) -> Result<DialInfo, RPCError> {
    let pt = reader.get_protocol_type();

    match pt {
        FOURCC_PROTOCOL_TYPE_UDP => {
            let udp = reader
                .get_detail()
                .get_as::<veilid_capnp::dial_info_u_d_p::Reader>()?;

            rpc_ignore_missing_property!(udp, socket_address);
            let socket_address_reader = udp.get_socket_address()?;
            let socket_address = decode_socket_address(&socket_address_reader)?;
            reject_unspecified_socket_address(&socket_address)?;
            Ok(DialInfo::udp(socket_address))
        }
        FOURCC_PROTOCOL_TYPE_TCP => {
            let tcp = reader
                .get_detail()
                .get_as::<veilid_capnp::dial_info_t_c_p::Reader>()?;

            rpc_ignore_missing_property!(tcp, socket_address);
            let socket_address_reader = tcp.get_socket_address()?;
            let socket_address = decode_socket_address(&socket_address_reader)?;
            reject_unspecified_socket_address(&socket_address)?;
            Ok(DialInfo::tcp(socket_address))
        }
        FOURCC_PROTOCOL_TYPE_WS => {
            let ws = reader
                .get_detail()
                .get_as::<veilid_capnp::dial_info_w_s::Reader>()?;

            rpc_ignore_missing_property!(ws, socket_address);
            let socket_address_reader = ws.get_socket_address()?;
            let socket_address = decode_socket_address(&socket_address_reader)?;
            reject_unspecified_socket_address(&socket_address)?;
            rpc_ignore_missing_property!(ws, request);
            let request = ws.get_request()?;
            DialInfo::try_ws(
                socket_address,
                request
                    .to_string()
                    .map_err(RPCError::map_protocol("invalid WS request string"))?,
            )
            .map_err(RPCError::map_protocol("invalid WS dial info"))
        }
        #[cfg(feature = "enable-protocol-wss")]
        FOURCC_PROTOCOL_TYPE_WSS => {
            let wss = reader
                .get_detail()
                .get_as::<veilid_capnp::dial_info_w_s_s::Reader>()?;

            rpc_ignore_missing_property!(wss, socket_address);
            let socket_address_reader = wss
                .get_socket_address()
                .map_err(RPCError::map_protocol("missing WSS socketAddress"))?;
            let socket_address = decode_socket_address(&socket_address_reader)?;
            reject_unspecified_socket_address(&socket_address)?;
            rpc_ignore_missing_property!(wss, request);
            let request = wss.get_request()?;
            DialInfo::try_wss(
                socket_address,
                request
                    .to_string()
                    .map_err(RPCError::map_protocol("invalid WSS request string"))?,
            )
            .map_err(RPCError::map_protocol("invalid WSS dial info"))
        }
        #[cfg(feature = "enable-protocol-webtransport")]
        FOURCC_PROTOCOL_TYPE_WTS | FOURCC_PROTOCOL_TYPE_WTD => {
            let wt = reader
                .get_detail()
                .get_as::<veilid_capnp::dial_info_web_transport::Reader>()?;

            rpc_ignore_missing_property!(wt, socket_address);
            let socket_address_reader = wt.get_socket_address()?;
            let socket_address = decode_socket_address(&socket_address_reader)?;
            reject_unspecified_socket_address(&socket_address)?;
            rpc_ignore_missing_property!(wt, request);
            let request = wt
                .get_request()?
                .to_string()
                .map_err(RPCError::map_protocol(
                    "invalid WebTransport request string",
                ))?;
            rpc_ignore_missing_property!(wt, cert_hashes);
            let cert_hashes_reader = wt.get_cert_hashes()?;
            rpc_ignore_max_len!(cert_hashes_reader, MAX_CERT_HASHES);
            let mut cert_hashes = Vec::<[u8; 32]>::with_capacity(cert_hashes_reader.len() as usize);
            for i in 0..cert_hashes_reader.len() {
                let h = cert_hashes_reader
                    .get(i)
                    .map_err(RPCError::map_protocol("invalid WebTransport cert hash"))?;
                let arr = <[u8; 32]>::try_from(h)
                    .map_err(|_| RPCError::ignore("WebTransport cert hash is not 32 bytes"))?;
                cert_hashes.push(arr);
            }
            let expiration = Some(Timestamp::new(wt.get_expiration())).filter(|x| !x.is_zero());
            if pt == FOURCC_PROTOCOL_TYPE_WTS {
                DialInfo::try_webtransport_stream(socket_address, request, cert_hashes, expiration)
                    .map_err(RPCError::map_protocol("invalid WebTransport dial info"))
            } else {
                DialInfo::try_webtransport_datagram(
                    socket_address,
                    request,
                    cert_hashes,
                    expiration,
                )
                .map_err(RPCError::map_protocol("invalid WebTransport dial info"))
            }
        }
        _ => Err(RPCError::ignore("unknown protocol type")),
    }
}

pub fn encode_dial_info(
    dial_info: &DialInfo,
    builder: &mut veilid_capnp::dial_info::Builder,
) -> Result<(), RPCError> {
    match dial_info {
        DialInfo::UDP(udp) => {
            builder.set_protocol_type(FOURCC_PROTOCOL_TYPE_UDP);
            let mut di_udp_builder = builder
                .reborrow()
                .init_detail()
                .init_as::<veilid_capnp::dial_info_u_d_p::Builder>();

            encode_socket_address(
                &udp.socket_address,
                &mut di_udp_builder.reborrow().init_socket_address(),
            )?;
        }
        DialInfo::TCP(tcp) => {
            builder.set_protocol_type(FOURCC_PROTOCOL_TYPE_TCP);
            let mut di_tcp_builder = builder
                .reborrow()
                .init_detail()
                .init_as::<veilid_capnp::dial_info_t_c_p::Builder>();

            encode_socket_address(
                &tcp.socket_address,
                &mut di_tcp_builder.reborrow().init_socket_address(),
            )?;
        }
        DialInfo::WS(ws) => {
            builder.set_protocol_type(FOURCC_PROTOCOL_TYPE_WS);
            let mut di_ws_builder = builder
                .reborrow()
                .init_detail()
                .init_as::<veilid_capnp::dial_info_w_s::Builder>();

            encode_socket_address(
                &ws.socket_address,
                &mut di_ws_builder.reborrow().init_socket_address(),
            )?;
            let request = dial_info
                .request()
                .ok_or_else(RPCError::else_internal("no request for WS dialinfo"))?;

            let mut requestb = di_ws_builder.init_request(
                request
                    .len()
                    .try_into()
                    .map_err(RPCError::map_protocol("request too long"))?,
            );
            requestb.push_str(request.as_str());
        }
        #[cfg(feature = "enable-protocol-wss")]
        DialInfo::WSS(wss) => {
            builder.set_protocol_type(FOURCC_PROTOCOL_TYPE_WSS);
            let mut di_wss_builder = builder
                .reborrow()
                .init_detail()
                .init_as::<veilid_capnp::dial_info_w_s_s::Builder>();

            encode_socket_address(
                &wss.socket_address,
                &mut di_wss_builder.reborrow().init_socket_address(),
            )?;
            let request = dial_info
                .request()
                .ok_or_else(RPCError::else_internal("no request for WSS dialinfo"))?;

            let mut requestb = di_wss_builder.init_request(
                request
                    .len()
                    .try_into()
                    .map_err(RPCError::map_protocol("request too long"))?,
            );
            requestb.push_str(request.as_str());
        }
        #[cfg(feature = "enable-protocol-webtransport")]
        DialInfo::WebTransportStream(wt) => {
            builder.set_protocol_type(FOURCC_PROTOCOL_TYPE_WTS);
            encode_dial_info_web_transport(wt, builder)?;
        }
        #[cfg(feature = "enable-protocol-webtransport")]
        DialInfo::WebTransportDatagram(wt) => {
            builder.set_protocol_type(FOURCC_PROTOCOL_TYPE_WTD);
            encode_dial_info_web_transport(wt, builder)?;
        }
    };
    Ok(())
}

#[cfg(feature = "enable-protocol-webtransport")]
fn encode_dial_info_web_transport(
    wt: &DialInfoWebTransport,
    builder: &mut veilid_capnp::dial_info::Builder,
) -> Result<(), RPCError> {
    let mut b = builder
        .reborrow()
        .init_detail()
        .init_as::<veilid_capnp::dial_info_web_transport::Builder>();

    encode_socket_address(&wt.socket_address, &mut b.reborrow().init_socket_address())?;
    {
        let mut requestb = b.reborrow().init_request(
            wt.request
                .len()
                .try_into()
                .map_err(RPCError::map_protocol("request too long"))?,
        );
        requestb.push_str(wt.request.as_str());
    }
    {
        let mut hashesb = b.reborrow().init_cert_hashes(
            wt.cert_hashes
                .len()
                .try_into()
                .map_err(RPCError::map_protocol("too many cert hashes"))?,
        );
        for (i, h) in wt.cert_hashes.iter().enumerate() {
            hashesb.set(i as u32, h.as_slice());
        }
    }
    b.set_expiration(wt.expiration.unwrap_or_default().as_u64());
    Ok(())
}
