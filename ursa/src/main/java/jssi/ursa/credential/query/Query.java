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

package jssi.ursa.credential.query;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class Query {

    private static final Logger LOG = LoggerFactory.getLogger(Query.class);

    private QueryOp op;
    private String key;
    private String value;
    private List<String> values = new ArrayList<>();
    private List<Query> operators = new ArrayList<>();

    public Query(QueryOp op, String key, String value) {
        this.op = op;
        this.key = key;
        this.value = value;
    }

    public Query(QueryOp op, String key, List<String> values) {
        this(op, key, "");
        this.values = values;
    }

    public Query(QueryOp op, List<Query> operators){
        this(op, null, "");
        this.operators = operators;
    }

    public QueryOp getOp(){
        return op;
    }

    public List<Query> getOperators() {
        return operators;
    }

    public String getKey() {
        return key;
    }

    public String getValue() {
        return value;
    }

    public List<String> getValues() {
        return values;
    }

    @Override
    public String toString(){
        switch (op){
            case Eq:
                return String.format("{\"%s\":\"%s\"}", key, value);
            case Neq:
                return String.format("{\"%s\":{\"$neq\":\"%s\"}}", key, value);
            case Gt:
                return String.format("{\"%s\":{\"$gt\":\"%s\"}}", key, value);
            case Gte:
                return String.format("{\"%s\":{\"$gte\":\"%s\"}}", key, value);
            case Lt:
                return String.format("{\"%s\":{\"$lt\":\"%s\"}}", key, value);
            case Lte:
                return String.format("{\"%s\":{\"$lte\":\"%s\"}}", key, value);
            case Like:
                return String.format("{\"%s\":{\"$like\":\"%s\"}}", key, value);
            case In:
                return String.format("{\"%s\":{\"$in\":[%s]}}", key, String.join(",", values));
            case And:{
                List<String> values = operators.stream().map(Query::toString).collect(Collectors.toList());
                return String.format("{\"$and\":[%s]}", String.join(",", values));
            }
            case Or:{
                List<String> values = operators.stream().map(Query::toString).collect(Collectors.toList());
                return String.format("{\"$or\":[%s]}", String.join(",", values));
            }
            case Not:{
                Query query =  operators.get(0);
                if(query.op == QueryOp.And && query.operators.size() == 0){
                    return String.format("{\"$not\":%s}", "{}");
                } else if(query.op == QueryOp.In){
                    return String.format("{\"$not\":[%s]}", query);
                } else {
                    return String.format("{\"$not\":%s}", query);
                }
            }
            default:{
                LOG.error(String.format("Unexpected query operation %s", op.name()));
                return null;
            }
        }
    }

    public static Query build(String query) throws JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode node = mapper.readTree(query);
        return parseQuery(node);
    }

    private Query optimize(){
        if(operators.size() == 1){
            return operators.remove(0);
        }
        return this;
    }

    private static Query parseQuery(JsonNode node){
        List<Query> operators = new ArrayList<>(node.size());
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();

        while(fields.hasNext()){
            Map.Entry<String, JsonNode> item = fields.next();
            operators.add(parseOperator(item.getKey(), item.getValue()));
        }
        return new Query(QueryOp.And, operators).optimize();
    }

    private static Query parseOperator(String key, JsonNode node){
        if(key.equals("$and") && node.isArray()) {
            List<Query> operators = parseOperators(node);
            return new Query(QueryOp.And, operators);
        } else if(key.equals("$or") && node.isArray()) {
            List<Query> operators = parseOperators(node);
            return new Query(QueryOp.Or, operators);
        } else if(key.equals("$not")){
            List<Query> operators = new ArrayList<>();
            operators.add(parseQuery(node.get(0) == null ? node : node.get(0)));
            return  new Query(QueryOp.Not, operators);
        } else if (node.isTextual()){
            return new Query(QueryOp.Eq, key, node.asText());
        } else if (node.size() == 1){
            return parse(key, node);
        }

        LOG.error("Unsupported value");
        return null;
    }

    private static List<Query> parseOperators(JsonNode node) {
        List<Query> operators = new ArrayList<>(node.size());
        for(JsonNode item : node){
            operators.add(parseQuery(item));
        }
        return operators;
    }

    private static Query parse(String key, JsonNode node){
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        Map.Entry<String, JsonNode> field = fields.next();

        switch(field.getKey()) {
            case "$neq":
                return new Query(QueryOp.Neq, key, field.getValue().asText());
            case "$gt":
                return new Query(QueryOp.Gt, key, field.getValue().asText());
            case "$gte":
                return new Query(QueryOp.Gte, key, field.getValue().asText());
            case "$lt":
                return new Query(QueryOp.Lt, key, field.getValue().asText());
            case "$lte":
                return new Query(QueryOp.Lte, key, field.getValue().asText());
            case "$like":
                return new Query(QueryOp.Like, key, field.getValue().asText());
            case "$in":{
                List<String> values = new ArrayList<>();
                for(JsonNode value : field.getValue()){
                    values.add(String.format("\"%s\"", value.asText()));
                }
                return new Query(QueryOp.In, key, values);
            }
            default:
                LOG.error("Unknown operator");
                return null;
        }
    }
}
