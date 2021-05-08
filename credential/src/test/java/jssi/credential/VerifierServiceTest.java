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

package jssi.credential;

import org.junit.jupiter.api.Test;
import jssi.credential.credential.CredentialDefinitionId;
import jssi.credential.proof.Identifier;
import jssi.credential.proof.NonRevokedInterval;
import jssi.credential.revocation.RevocationRegistryId;
import jssi.credential.schema.SchemaId;
import jssi.ursa.credential.query.Query;
import jssi.ursa.credential.query.QueryOp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertTrue;

class VerifierServiceTest {

    private static final String SCHEMA_ID = "123";
    private static final String SCHEMA_NAME = "Schema Name";
    private static final String SCHEMA_ISSUER_DID = "234";
    private static final String SCHEMA_VERSION = "1.2.3";
    private static final String CRED_DEF_ID = "345";
    private static final String ISSUER_DID = "456";

    private String schema_id_tag() { return "schema_id"; }

    private String schema_name_tag() { return "schema_name"; }

    private String schema_issuer_did_tag() { return "schema_issuer_did"; }

    private String schema_version_tag() { return "schema_version"; }

    private String cred_def_id_tag() { return "cred_def_id"; }

    private String issuer_did_tag() { return "issuer_did"; }

    private String attr_tag() { return "attr::zip::marker"; }

    private String attr_tag_value() { return "attr::zip::value"; }

    private String bad_attr_tag() { return "bad::zip::marker"; }

     private Filter filter() {
        return new Filter(
                SCHEMA_ID,
                SCHEMA_ISSUER_DID,
                SCHEMA_NAME,
                SCHEMA_VERSION,
                ISSUER_DID,
                CRED_DEF_ID);
    }

    @Test
    void processOpEq() {
        Filter filter = filter();

        Query op = new Query (QueryOp.Eq, schema_id_tag(), SCHEMA_ID);
        assertTrue(VerifierService.processOperator("zip", op, filter, null));

        List<Query> operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, attr_tag(),"1"));
        operators.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));

        op = new Query (QueryOp.And, operators);
        assertTrue(VerifierService.processOperator("zip", op, filter, null));

        operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, bad_attr_tag(),"1"));
        operators.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));

        op = new Query (QueryOp.And, operators);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));

        op = new Query(QueryOp.Eq, schema_id_tag(), "NOT HERE");
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));
    }

    @Test
    void processOpNeq() {
        Filter filter = filter();

        Query op = new Query(QueryOp.Neq, schema_id_tag(), SCHEMA_ID);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));

        op = new Query(QueryOp.Neq, schema_id_tag(), "NOT HERE");
        assertTrue(VerifierService.processOperator("zip", op, filter, null));
    }

    @Test
    void processOpIn() {

        Filter filter = filter();
        List<String> cred_def_ids = new ArrayList<>();
        cred_def_ids.add("Not Here");

        Query op = new Query(QueryOp.In, cred_def_id_tag(), cred_def_ids);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));

        cred_def_ids.add(CRED_DEF_ID);
        op = new Query(QueryOp.In, cred_def_id_tag(), cred_def_ids);
        assertTrue(VerifierService.processOperator("zip", op, filter, null));
    }

    @Test
    void processOpOr() {
        Filter filter = filter();

        List<Query> operators = new ArrayList<>();

        operators.add(new Query(QueryOp.Eq, schema_id_tag(), "Not Here"));
        operators.add(new Query(QueryOp.Eq, cred_def_id_tag(), "Not Here"));

        Query op = new Query (QueryOp.Or, operators);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));

        operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));
        operators.add(new Query(QueryOp.Eq, cred_def_id_tag(), "Not Here"));
        op = new Query (QueryOp.Or, operators);
        assertTrue(VerifierService.processOperator("zip", op, filter, null));
    }

    @Test
    void processOpAnd() {
        Filter filter = filter();

        List<Query> operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, schema_id_tag(), "Not Here"));
        operators.add(new Query(QueryOp.Eq, cred_def_id_tag(), "Not Here"));

        Query op = new Query (QueryOp.And, operators);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));

        operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));
        operators.add(new Query(QueryOp.Eq, cred_def_id_tag(), "Not Here"));
        op = new Query (QueryOp.And, operators);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));

        operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));
        operators.add(new Query(QueryOp.Eq, cred_def_id_tag(), CRED_DEF_ID));
        op = new Query (QueryOp.And, operators);
        assertTrue(VerifierService.processOperator("zip", op, filter, null));
    }

    @Test
    void processOpNot() {
        Filter filter = filter();

        List<Query> operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));
        operators.add(new Query(QueryOp.Eq, cred_def_id_tag(), CRED_DEF_ID));

        List<Query> ops = new ArrayList<>();
        ops.add(new Query (QueryOp.And, operators));
        Query op = new Query(QueryOp.Not, ops);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));

        operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, schema_id_tag(), "Not Here"));
        operators.add(new Query(QueryOp.Eq, cred_def_id_tag(), "Not Here"));

        ops = new ArrayList<>();
        ops.add(new Query (QueryOp.And, operators));
        op = new Query(QueryOp.Not, ops);
        assertTrue(VerifierService.processOperator("zip", op, filter, null));
    }

    @Test
    void processOpOrWithNestedAnd() {
        Filter filter = filter();

        List<Query> operators1 = new ArrayList<>();
        operators1.add(new Query(QueryOp.Eq, schema_id_tag(), "Not Here"));
        operators1.add(new Query(QueryOp.Eq, cred_def_id_tag(), "Not Here"));
        Query op1 = new Query (QueryOp.And, operators1);

        List<Query> operators2 = new ArrayList<>();
        operators2.add(new Query(QueryOp.Eq, schema_issuer_did_tag(), "Not Here"));
        operators2.add(new Query(QueryOp.Eq, schema_name_tag(), "Not Here"));
        Query op2 = new Query (QueryOp.And, operators2);

        List<Query> operators3 = new ArrayList<>();
        operators3.add(new Query(QueryOp.Eq, schema_name_tag(), "Not Here"));
        operators3.add(new Query(QueryOp.Eq, issuer_did_tag(), "Not Here"));
        Query op3 = new Query (QueryOp.And, operators3);

        List<Query> ops = new ArrayList<>();
        ops.add(op1);
        ops.add(op2);
        ops.add(op3);
        Query op = new Query(QueryOp.Or, ops);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));


        operators1 = new ArrayList<>();
        operators1.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));
        operators1.add(new Query(QueryOp.Eq, cred_def_id_tag(), "Not Here"));
        op1 = new Query (QueryOp.And, operators1);

        operators2 = new ArrayList<>();
        operators2.add(new Query(QueryOp.Eq, schema_issuer_did_tag(), "Not Here"));
        operators2.add(new Query(QueryOp.Eq, schema_name_tag(), "Not Here"));
        op2 = new Query (QueryOp.And, operators2);

        operators3 = new ArrayList<>();
        operators3.add(new Query(QueryOp.Eq, schema_name_tag(), "Not Here"));
        operators3.add(new Query(QueryOp.Eq, issuer_did_tag(), "Not Here"));
        op3 = new Query (QueryOp.And, operators3);

        ops = new ArrayList<>();
        ops.add(op1);
        ops.add(op2);
        op = new Query(QueryOp.Or, ops);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));

        operators1 = new ArrayList<>();
        operators1.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));
        operators1.add(new Query(QueryOp.Eq, cred_def_id_tag(), CRED_DEF_ID));
        op1 = new Query (QueryOp.And, operators1);

        operators2 = new ArrayList<>();
        operators2.add(new Query(QueryOp.Eq, schema_issuer_did_tag(), "Not Here"));
        operators2.add(new Query(QueryOp.Eq, schema_name_tag(), "Not Here"));
        op2 = new Query (QueryOp.And, operators2);

        operators3 = new ArrayList<>();
        operators3.add(new Query(QueryOp.Eq, schema_name_tag(), "Not Here"));
        operators3.add(new Query(QueryOp.Eq, issuer_did_tag(), "Not Here"));
        op3 = new Query (QueryOp.And, operators3);

        ops = new ArrayList<>();
        ops.add(op1);
        ops.add(op2);
        op = new Query(QueryOp.Or, ops);
        assertTrue(VerifierService.processOperator("zip", op, filter, null));
    }

    @Test
    void processOpComplex() {
        Filter filter = filter();

        List<Query> or = new ArrayList<>();
        or.add(new Query(QueryOp.Eq, schema_id_tag(), "Not Here"));
        or.add(new Query(QueryOp.Eq, cred_def_id_tag(), "Not Here"));

        List<Query> and1 = new ArrayList<>();
        and1.add(new Query (QueryOp.Or, or));
        and1.add(new Query(QueryOp.Eq, schema_id_tag(), "Not Here"));
        and1.add(new Query(QueryOp.Eq, cred_def_id_tag(), "Not Here"));
        Query op1 = new Query (QueryOp.And, and1);

        List<Query> and2 = new ArrayList<>();
        and2.add(new Query(QueryOp.Eq, schema_issuer_did_tag(), SCHEMA_ISSUER_DID));
        and2.add(new Query(QueryOp.Eq, schema_name_tag(), SCHEMA_NAME));
        Query op2 = new Query (QueryOp.And, and2);

        List<Query> and3 = new ArrayList<>();
        and3.add(new Query(QueryOp.Eq, schema_version_tag(), SCHEMA_VERSION));
        and3.add(new Query(QueryOp.Eq, issuer_did_tag(), ISSUER_DID));
        Query op3 = new Query (QueryOp.And, and3);

        List<Query> ops = new ArrayList<>();
        ops.add(op1);
        ops.add(op2);
        ops.add(op3);
        Query op = new Query(QueryOp.And, ops);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));


        or = new ArrayList<>();
        or.add(new Query(QueryOp.Eq, schema_name_tag(), SCHEMA_NAME));
        or.add(new Query(QueryOp.Eq, issuer_did_tag(), "Not Here"));

        and1 = new ArrayList<>();
        and1.add(new Query (QueryOp.Or, or));
        and1.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));
        and1.add(new Query(QueryOp.Eq, cred_def_id_tag(), CRED_DEF_ID));
        op1 = new Query (QueryOp.And, and1);

        and2 = new ArrayList<>();
        and2.add(new Query(QueryOp.Eq, schema_issuer_did_tag(), SCHEMA_ISSUER_DID));
        and2.add(new Query(QueryOp.Eq, schema_name_tag(), SCHEMA_NAME));
        op2 = new Query (QueryOp.And, and2);

        and3 = new ArrayList<>();
        and3.add(new Query(QueryOp.Eq, schema_version_tag(), SCHEMA_VERSION));
        and3.add(new Query(QueryOp.Eq, issuer_did_tag(), ISSUER_DID));
        op3 = new Query (QueryOp.And, and3);

        List<Query> not = new ArrayList<>();
        not.add(new Query(QueryOp.Eq, schema_version_tag(), "Not Here"));
        Query op4 = new Query(QueryOp.Not, not);

        ops = new ArrayList<>();
        ops.add(op1);
        ops.add(op2);
        ops.add(op3);
        ops.add(op4);
        op = new Query(QueryOp.And, ops);
        assertTrue(VerifierService.processOperator("zip", op, filter, null));

        or = new ArrayList<>();
        or.add(new Query(QueryOp.Eq, schema_name_tag(), SCHEMA_NAME));
        or.add(new Query(QueryOp.Eq, issuer_did_tag(), "Not Here"));

        and1 = new ArrayList<>();
        and1.add(new Query (QueryOp.Or, or));
        and1.add(new Query(QueryOp.Eq, schema_id_tag(), SCHEMA_ID));
        and1.add(new Query(QueryOp.Eq, cred_def_id_tag(), CRED_DEF_ID));
        op1 = new Query (QueryOp.And, and1);

        and2 = new ArrayList<>();
        and2.add(new Query(QueryOp.Eq, schema_issuer_did_tag(), SCHEMA_ISSUER_DID));
        and2.add(new Query(QueryOp.Eq, schema_name_tag(), SCHEMA_NAME));
        op2 = new Query (QueryOp.And, and2);

        and3 = new ArrayList<>();
        and3.add(new Query(QueryOp.Eq, schema_version_tag(), SCHEMA_VERSION));
        and3.add(new Query(QueryOp.Eq, issuer_did_tag(), ISSUER_DID));
        op3 = new Query (QueryOp.And, and3);

        not = new ArrayList<>();
        not.add(new Query(QueryOp.Eq, schema_version_tag(), SCHEMA_VERSION));
        op4 = new Query(QueryOp.Not, not);

        ops = new ArrayList<>();
        ops.add(op1);
        ops.add(op2);
        ops.add(op3);
        ops.add(op4);
        op = new Query(QueryOp.And, ops);
        assertTrue(!VerifierService.processOperator("zip", op, filter, null));
    }


    @Test
    void processOpRevealed() {
        Filter filter = filter();
        String value = "value";

        Query op = new Query(QueryOp.Eq, attr_tag_value(), value);
        assertTrue(VerifierService.processOperator("zip", op, filter, value));

        List<Query> operators = new ArrayList<>();
        operators.add(new Query(QueryOp.Eq, attr_tag_value(), value));
        operators.add(new Query(QueryOp.Eq, schema_issuer_did_tag(), SCHEMA_ISSUER_DID));
        op = new Query (QueryOp.And, operators);
        assertTrue(VerifierService.processOperator("zip", op, filter, value));

        op = new Query(QueryOp.Eq, attr_tag_value(), value);
        assertTrue(!VerifierService.processOperator("zip", op, filter, "Not here"));
    }

    private Map<String, Identifier> received() {
        Map<String, Identifier> result = new HashMap<>();
        result.put(
                "referent_1",
                new Identifier(
                        new SchemaId(null),
                        new CredentialDefinitionId(null),
                        new RevocationRegistryId(null), Long.valueOf(1234)));

        result.put(
                "referent_2",
                new Identifier(
                        new SchemaId(null),
                        new CredentialDefinitionId(null),
                        new RevocationRegistryId(null), null));

        return result;

    }

    private NonRevokedInterval interval()  {
        return new NonRevokedInterval(null, Long.valueOf(1234)) ;
    }

    @Test
    void validateTimestamp() {
        assertTrue(VerifierService.validateTimestamp(received(), "referent_1", null, null));
        assertTrue(VerifierService.validateTimestamp(received(), "referent_1", interval(), null));
        assertTrue(VerifierService.validateTimestamp(received(), "referent_1", null, interval()));

        assertTrue(!VerifierService.validateTimestamp(received(), "referent_2", interval(), null));
        assertTrue(!VerifierService.validateTimestamp(received(), "referent_2", null, interval()));
        assertTrue(!VerifierService.validateTimestamp(received(), "referent_3", null, interval()));
    }

    @Test
    void isAttributeInternalTag(){
        Map<String, String> map = new HashMap<>();
        map.put("zip", null); //attr::zip::marker

        assertTrue(VerifierService.isAttributeInternalTag("attr::zip::marker", map));
        assertTrue(VerifierService.isAttributeInternalTag("attr::zip::value", map));
        assertTrue(!VerifierService.isAttributeInternalTag("bad::zip::value", map));
    }
}