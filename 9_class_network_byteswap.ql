import cpp
class NetworkByteSwap extends Expr {
  NetworkByteSwap () {

    exists (MacroInvocation i |
         i.getMacroName() in ["ntohs", "ntohl", "ntohl"] and
         this = i.getExpr()
    )
     
  }
}

from NetworkByteSwap n
select n, "Network byte swap"