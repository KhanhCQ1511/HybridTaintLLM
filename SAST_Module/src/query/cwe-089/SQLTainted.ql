/**
 * @name SQL query influenced by user input
 * @description A SQL query is constructed using user-controlled data, which could allow SQL injection attacks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/sql-injection-path
 * @tags security
 *       external/cwe/cwe-089
 *       external/cwe/cwe-564
 */

import java
import semmle.code.java.security.SqlInjectionQuery
import QueryInjectionFlow::PathGraph

from
  QueryInjectionFlow::PathNode source, QueryInjectionFlow::PathNode sink
where
  QueryInjectionFlow::flowPath(source, sink)
select
  source.getNode().getEnclosingCallable().getDeclaringType().getQualifiedName(),
  source.getNode().getEnclosingCallable().getName(),
  source.getNode().toString(),
  source.getNode().getLocation().getStartLine(),
  sink.getNode().getEnclosingCallable().getDeclaringType().getQualifiedName(),
  sink.getNode().getEnclosingCallable().getName(),
  sink.getNode().toString(),
  sink.getNode().getLocation().getStartLine()