/**
 * @name Uncontrolled data used in path expression
 * @description Accessing paths influenced by users can allow an attacker to access unexpected resources.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision high
 * @id java/path-injection
 * @tags security
 *       external/cwe/cwe-022
 *       external/cwe/cwe-023
 *       external/cwe/cwe-036
 *       external/cwe/cwe-073
 */

import java
import semmle.code.java.security.TaintedPathQuery
import TaintedPathFlow::PathGraph

from TaintedPathFlow::PathNode source, TaintedPathFlow::PathNode sink
where TaintedPathFlow::flowPath(source, sink)
select
  source.getNode().getEnclosingCallable().getDeclaringType().getQualifiedName(),
  source.getNode().getEnclosingCallable().getName(),
  source.getNode().toString(),
  source.getNode().getLocation().getStartLine(),
  sink.getNode().getEnclosingCallable().getDeclaringType().getQualifiedName(),
  sink.getNode().getEnclosingCallable().getName(),
  sink.getNode().toString(),
  sink.getNode().getLocation().getStartLine()