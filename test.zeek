global IPuserTable: table[addr] of set[string] = table();

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
     if(c$http?$user_agent) {
          local source_address: addr = c$id$orig_h;
          local useragent: string = to_lower(c$http$user_agent);
          if(source_address in IPuserTable) {
               add IPuserTable[source_address][useragent];
          }
          else {
               IPuserTable[source_address] = set(useragent);
          }
     }
}

event zeek_done()
{
     for(source_address in IPuserTable) {
          if(|IPuserTable[source_address]| >= 3) {
               print fmt("%s is a proxy", source_address);
          }
     }
}
