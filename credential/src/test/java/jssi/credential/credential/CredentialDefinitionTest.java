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

package jssi.credential.credential;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.ToStringSerializer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class CredentialDefinitionTest {

    @Test
    void json_test() throws IOException {

        SimpleModule module = new SimpleModule();
        module.addSerializer(BigInteger.class, new ToStringSerializer());


        String json = "{\"id\":\"2hoqvcwupRTUNkXn6ArYzs:3:CL:2471\",\"schemaId\":\"2471\",\"type\":\"CL\",\"tag\":\"\",\"value\":{\"primary\":{\"n\":\"86724287350477751206656570979032966703329505889109970100672593600212159710122524558840987784946586074662132488236400738181991816412026591140984921370179767079606062874849350699068544007953394425621170412614434471437870413981961728213356970896311390324401528063993712079175929421151002066958792621968526123052543362726709351064982035483300909753311188927834431210143615918489181734829742678671085195486779344279087570275333764801067819032638761795735427697089756560490683732524286268242592541483561421003008848905312960263229239327096444856373881655366169784000740449827583427336247268796008957239930929940106124383441\",\"s\":\"68565823032708474306514409710254746185097024905866456492400609548513882080060651547254886717209317635536647955345162687060898443709138147278667084384903589486496041039093776147061990629509796556903457618318946948477020316739616698285098064517065210309432231348425794038491136239768243653004282415622183771020331818660661942833453261537705421796886050819425946416534064887172474631878946648680969678450250632713392749852095439858412085632624401434183699289763190966729771549896627986528002008455144081216013915376906960616224100785288425229004552127157820129850247623860663716001315305824246521524314406787572201936159\",\"r\":{\"name\":\"21470694100729869744261292006763813345150044183446029540177870124524039106316094174460389232832571532284810170007293388299473733141322565289343893281311432223107289867486737597507381929324412597111791890822982978607377646493268665410154158352332552430455410676424655538131806962743837140975034501945349610114128040516920426419752180449876110429631390074018339624366625706057577988994157784979295579958266166722663022918076663412107247120922543421973109778231583641494528977463571610522286622037737315024310026589510134042108138559662654575330826743445692198806461970153226357910705261181205457260549327597981951573985\",\"height\":\"13939356647759609174485719802501773567276049548245424935504126500265586608662951980260718040791134755864486701853050225651855956737901595730976263505088594378380074293405559194748221759603581890598079117782820527925868489919600695104312261805970657325246956081208878862007439057712465023318674543859367201399080194572966833003881512520725074633033420930095211305635173717467241968613481516063152487980820555533755239133651769565133420156114776578165410212221881994925880629770028898705859268663836663647027677768478228049082189465977511902707373041793879289766830466362779198318255196657839703097701957436211432866940\",\"sex\":\"20022101741446570264557630399489699993011383357495333780962515915463701761385865327966524872646907887816919241795166812245521381526599594939708271733894974601885444697364264320467230587792262093722414489552649750887746173699408773581709694927717324336563255309885303903452791340447296644230298702852495919610048570998314143211678209843631329899528727189541506380135323384697685129288034139901316951883056009308816474794904871533784876333707034390658024899757223718233822416033410932755695918855013227912649125625613708302826940395050959425506559689930729589702715565613350872257404294852981485742693414175561560376878\",\"age\":\"68324431017386373141723313379588123114122172733785498028129098771912332870161622586830226725832682089282797682478996628527458521203981066532148542867910727876973540501604298386964941331385945509447921573334640257131480681017298967411615851997278468982114318053852745062107685596645860574744820479443008568550713733647938784629517351521220040117482812057845591724691129906359015250113706837112935971415735663780322204054449465947028328022534972551186400163012220719718039176357586730457386744557089473465341563472760872536594611618365110919837962302554808225102415883187587908311141004150113254350300861684974387245524\"},\"rctxt\":\"28968968789316921956195020159043701485128084666788319688919703768305257857030853826651494435280634703130965749799263847281089261890586404514554128897545567559411392274924672850695923428556666839524191639557540925894441247523915911594915810062115573022491175505153277512476305377826383134343681670368530974886362266706187655064207938621808588725531887931062314044094064943783008218642721898688548716600959291789899808528982572786472183338043212505885146997913313141282478028502666021364027851488363355869491118603841447843857893374823843951923935275949332495109370644946403701670919133621008245580388712016814216268114\",\"z\":\"86577229265747009560052615679615895419349481058284021085673929260636969170535560390660022683481326803220581815884464749038506104457182906050929596940529151731519096012460995580213574923115394453664191902057791953043346629148369777542113599040511920597866451649154423915282977750060280596799442262757753909295114858121438822608110664099684925371671089644086196379734044256966499814680946051154187391597679900273906654730748525684870945928000260002993274218927561839707361816863918092159839143300439497578075981381842189307826991559468115699410540879665465127893208243916471732332308562108973634353200261591256745812234\"}}}";

        ObjectMapper mapper = new ObjectMapper()
                .registerModule(module)
                .setSerializationInclusion(JsonInclude.Include.NON_NULL)
                .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);
        CredentialDefinition definition = mapper.readValue(json, CredentialDefinition.class);
        String result = mapper.writeValueAsString(definition);
        assertNotNull(definition);
    }

}