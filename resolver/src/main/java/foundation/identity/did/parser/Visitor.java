/*
 *  Copyright 2013 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/* -----------------------------------------------------------------------------
 * Visitor.java
 * -----------------------------------------------------------------------------
 *
 * Producer : com.parse2.aparse.Parser 2.5
 * Produced : Mon Jul 13 23:12:39 CEST 2020
 *
 * -----------------------------------------------------------------------------
 */

package foundation.identity.did.parser;

public interface Visitor
{
  public Object visit(Rule_did rule);
  public Object visit(Rule_method_name rule);
  public Object visit(Rule_method_char rule);
  public Object visit(Rule_method_specific_id rule);
  public Object visit(Rule_idchar rule);
  public Object visit(Rule_did_url rule);
  public Object visit(Rule_did_query rule);
  public Object visit(Rule_param rule);
  public Object visit(Rule_param_name rule);
  public Object visit(Rule_param_value rule);
  public Object visit(Rule_path_abempty rule);
  public Object visit(Rule_segment rule);
  public Object visit(Rule_pchar rule);
  public Object visit(Rule_query rule);
  public Object visit(Rule_fragment rule);
  public Object visit(Rule_pct_encoded rule);
  public Object visit(Rule_unreserved rule);
  public Object visit(Rule_reserved rule);
  public Object visit(Rule_gen_delims rule);
  public Object visit(Rule_sub_delims rule);
  public Object visit(Rule_ALPHA rule);
  public Object visit(Rule_DIGIT rule);
  public Object visit(Rule_HEXDIG rule);

  public Object visit(Terminal_StringValue value);
  public Object visit(Terminal_NumericValue value);
}

/* -----------------------------------------------------------------------------
 * eof
 * -----------------------------------------------------------------------------
 */
