/**
 * @name Uncontrolled command line
 * @description Using externally controlled strings in a command line is vulnerable to malicious
 *              changes in the strings.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id java/command-line-injection
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 */

import java
import semmle.code.java.security.CommandLineQuery
import InputToArgumentToExecFlow::PathGraph

from
  InputToArgumentToExecFlow::PathNode source,
  InputToArgumentToExecFlow::PathNode sink
where
  InputToArgumentToExecFlow::flowPath(source, sink)
select
  source.getNode().getEnclosingCallable().getDeclaringType().getQualifiedName(),
  source.getNode().getEnclosingCallable().getName(),
  source.getNode().toString(),
  source.getNode().getLocation().getStartLine(),
  sink.getNode().getEnclosingCallable().getDeclaringType().getQualifiedName(),
  sink.getNode().getEnclosingCallable().getName(),
  sink.getNode().toString(),
  sink.getNode().getLocation().getStartLine()