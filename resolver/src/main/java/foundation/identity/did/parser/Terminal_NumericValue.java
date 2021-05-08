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
 * Terminal_NumericValue.java
 * -----------------------------------------------------------------------------
 *
 * Producer : com.parse2.aparse.Parser 2.5
 * Produced : Mon Jul 13 23:12:39 CEST 2020
 *
 * -----------------------------------------------------------------------------
 */

package foundation.identity.did.parser;

import java.util.ArrayList;
import java.util.regex.Pattern;

public class Terminal_NumericValue extends Rule
{
  private Terminal_NumericValue(String spelling, ArrayList<Rule> rules)
  {
    super(spelling, rules);
  }

  public static Terminal_NumericValue parse(
    ParserContext context, 
    String spelling, 
    String regex, 
    int length)
  {
    context.push("NumericValue", spelling + "," + regex);

    boolean parsed = true;

    Terminal_NumericValue numericValue = null;
    try
    {
      String value = 
        context.text.substring(
          context.index, 
          context.index + length);

      if ((parsed = Pattern.matches(regex, value)))
      {
        context.index += length;
        numericValue = new Terminal_NumericValue(value, null);
      }
    }
    catch (IndexOutOfBoundsException e) {parsed = false;}

    context.pop("NumericValue", parsed);

    return numericValue;
  }

  public Object accept(Visitor visitor)
  {
    return visitor.visit(this);
  }
}
/* -----------------------------------------------------------------------------
 * eof
 * -----------------------------------------------------------------------------
 */
