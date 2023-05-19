module pDNS;

export {

#  query       | type |    answer     | count | ttl |     first     |    last


	redef enum Log::ID += { LOG };

	type Info: record {
		query: string;
		qtype_name: string;
		answers:vector of string ;
		seen_count: count;
		TTLs: vector of interval;
		first: time;
		last: time;
	} &log;

	global apdns: table[string] of Info &create_expire=1 mins;
}


event zeek_init()
    {
    Log::create_stream(pDNS::LOG, [$columns=Info, $path="pdns"]);

    local filter: Log::Filter =
        [
        $name="sqlite",
        $path="/tmp/pdns",
        $config=table(["tablename"] = "pDNS"),
        $writer=Log::WRITER_SQLITE
        ];

     Log::add_filter(pDNS::LOG, filter);
    }


event DNS::log_dns( rec: DNS::Info)
{

	#print fmt ("%s", rec);

	if (rec?$query && rec?$answers && rec?$qtype_name)
	{
		local prec: Info= [$query=rec$query, $qtype_name=rec$qtype_name, $seen_count=1, $answers=rec$answers, $TTLs=rec$TTLs, $first=rec$ts, $last=rec$ts];
		Log::write(pDNS::LOG, prec);



	}

}
