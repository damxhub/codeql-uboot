/**
 * @kind path-problem
 */

import cpp
// below imports taintTracking classes
import semmle.code.cpp.dataflow.TaintTracking
// below imports DataFlow predicates Node, source, sink
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap () {
        // the exists has a side effect of assigning this (a class instance)
        // to returned expression (i.getExpr)
        exists (MacroInvocation i |
             i.getMacroName() in ["ntohs", "ntohl", "ntohl"] and
             this = i.getExpr()
        ) 
    }
}

// extend TaintTracking::Configuration for each use
class Config extends TaintTracking::Configuration {
    // Config is a constructor that takes a momment
  Config() { this = "NetworkToMemFuncLength analysis by DAM" }
    override predicate isSource(DataFlow::Node source) {
       source.asExpr() instanceof NetworkByteSwap 
    }
    override predicate isSink(DataFlow::Node sink) {
        // get FunctionCalls for memcpy that pass expression as second
        // memcpy argument -- arguments start at 0 and 2nd for memcpy is length
        exists (FunctionCall c |
             c.getTarget().getName() = "memcpy" and
             sink.asExpr() = c.getArgument(2)
        )
    }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"
