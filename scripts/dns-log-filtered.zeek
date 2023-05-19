module pDNS;

const timestamps_json = "JSON::TS_MILLIS" &redef;

hook DNS::dns_filtered(rec: DNS::Info, id: Log::ID, filter: Log::Filter)
    {
    # Let's only log incomplete flows:
    if ( ! rec$RA )
        break;
    }

event zeek_init()
    {
    # Add a new filter to the Conn::LOG stream that logs only
    # timestamp and originator address.

    local filter: Log::Filter = [$name="dns", $path="dns_filtered", $config=table( ["use_json"] = "T", ["json_timestamps"] = timestamps_json),
                                 $include=set("ts", "id.resp_h","query","qtype_name", "RA", "answers", "TTLs"),
				 $policy=dns_filtered];
    Log::add_filter(DNS::LOG, filter);
    }

