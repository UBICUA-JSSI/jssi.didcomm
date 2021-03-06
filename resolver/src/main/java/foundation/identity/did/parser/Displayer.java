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
 * Displayer.java
 * -----------------------------------------------------------------------------
 *
 * Producer : com.parse2.aparse.Parser 2.5
 * Produced : Mon Jul 13 23:12:39 CEST 2020
 *
 * -----------------------------------------------------------------------------
 */

package foundation.identity.did.parser;

import java.util.ArrayList;

public class Displayer implements Visitor
{

  public Object visit(Rule_did rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_method_name rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_method_char rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_method_specific_id rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_idchar rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_did_url rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_did_query rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_param rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_param_name rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_param_value rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_path_abempty rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_segment rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_pchar rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_query rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_fragment rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_pct_encoded rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_unreserved rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_reserved rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_gen_delims rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_sub_delims rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_ALPHA rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_DIGIT rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Rule_HEXDIG rule)
  {
    return visitRules(rule.rules);
  }

  public Object visit(Terminal_StringValue value)
  {
    System.out.print(value.spelling);
    return null;
  }

  public Object visit(Terminal_NumericValue value)
  {
    System.out.print(value.spelling);
    return null;
  }

  public Object visitRules(ArrayList<Rule> rules)
  {
    for (Rule rule : rules)
      rule.accept(this);
    return null;
  }
}

/* -----------------------------------------------------------------------------
 * eof
 * -----------------------------------------------------------------------------
 */
