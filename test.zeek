global IPuserTable: table[addr] of set[string] = table();

event http_header_user_agent(c: connection, is_orig: bool, )




event zeek_done()
{
     for(source_address in IPuserTable) {
          if(|IPuserTable[source_address]| >= 3) {
               print fmt("%s is a proxy", source_address);
          }
     }
}
