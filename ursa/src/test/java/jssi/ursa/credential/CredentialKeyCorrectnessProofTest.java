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

package jssi.ursa.credential;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CredentialKeyCorrectnessProofTest {

    @Test
    void deserialize_test() {

        String data = "{" +
                "\"c\":\"37611675737093606611354469283892411880852495117565168932358663398963131397507\"," +
                "\"xz_cap\":\"81579130320284221659747319740108875652446580605626929564515869699158446225972801134098632494713496313081314380866687966418290227597750899002882970519534702423347828404017509366494708523530025686292969865053261834885716665417122559158656847219251019258307743208838075692695164262680850087806525721184647037789559371016575764323904037635266872661253754958239070844593676990703001641163014837607074604574439994741936613409912802229927895424755757352646030336597690950842465911939873272966620342405909930599727835739699655473154455657878429132861698360924836632047016333549106122684361100949241413364697739541658923119788014990949301155631757300624437448380216292364426202602100074188682993006187\"," +
                "\"xr_cap\":[" +
                "       [\"sex\",\"800280099800023684394221657855578281425593426428797438278634535803826854973287741112297002561462044581730457464290768546940348121889048006353304776646794823653560200707175243576534399257694825778643847023451169693956070462522652667711052051119060371846591706152099200381794609252833996514839617453462295422079364560725012355479350713908774407072059863925714626035129287654437915380442859411132043551952897474887960834654566958110046975477442837252851593858380406893298039998278146813948374557719947480415431505168848477644721410506100843223565186964968463081686726318431810101100839476456665117568759117498622946466335362502138675885007428245786030655866656241152568981953362753866546347245506\"]," +
                "       [\"age\",\"588088631461299425903748636894451597454180996508770107860820879608066278697726969676142820725979998876687628461524297952569445512912113947952863000770341397107329530774939533674792868680827566279577518607195225037390604727483704420911912238224219864823492245908348105557153285313698657725038609899106209002384198903035975551652419617009072704552236735717389754124395458798446740853188430442908535423980999434501037185906780341482928855355637070027953698599569975766436241558834373873737728336703980967063844033141464829186289408341005936078717542471679931243178369744750036706021440802187762189222523038598747576436835546143611288733061739572462869076736405341538116562816483588163276630145588\"]," +
                "       [\"height\",\"553220455491285418654889779078476533199565266037716057819253262456706086296310865820014979289644399892322745082334493480377902246036427120996737141182672228618720768916010742192428961333242647461723166430891725984061962166185290028781330840468287369467210902803713581463138002887245708126181113498506095878475477562185158200076760989353034954621747102865883089591566895303014875251551529870810800964290188402770835695975293408858132429212162793578010820152709965777440582153499339685425754384078776656170709303540365276228433474426237479107459583876421876578975913079855215398240111839997147164550277110095530104844265258104360762567118292063538492192083952712713837994596074547775217382719579\"]," +
                "       [\"name\",\"383325619072931698489524170594499308335325217367787209202882000237923187775119979058633557703022426956865524033530017842216102964924733310029537256438963746099184641563671420576298749176202668215626084998168583932862834827081323228031589641597768136343232183260789201414439414019145929237988915293970815065021922162304853953719973584719975042952713084160885042865916208477614187377876264496125987756268019899327470534991407455234648438185065303663808513544394761315253646500213994569448735987674657147571753166712102581100080484612181607406695322516789021386859985149430517261727189786324895636842320235453633433344220062995558348664785301570376489352431483740437508437906549673849465012384545\"]" +
                "   ]" +
                "}";


        CredentialKeyCorrectnessProof credentialKeyCorrectnessProof = null;
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            credentialKeyCorrectnessProof = objectMapper.readValue(data, CredentialKeyCorrectnessProof.class);
        } catch (JsonProcessingException e){
            assertNotNull(null);
        }
        assertNotNull(credentialKeyCorrectnessProof);
    }
}