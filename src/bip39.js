/**
 ****************************************************** 
 * @file    bip39.js
 * @file    Bitcoin bip39 implementation : mnemonic phrase <=> seed for bip32 HdWallet
 * @author  pad@maitrebitcoin.com
 * @module  js-bitcoin-criptolib
 * @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * 
 * @license LGPL-3.0 
 ******************************************************
 */


/**
 *  convert a mnemonic pharase to a buffer that can be used as a seed
 * @param {string} mnemonicPhrase UTF-8 NFKD phrase. ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
 * @param {string} [password] optionnal additional password. 
 * @return {string} 512 bits seed
 */
function seedFromPhrase(  mnemonicPhrase,  password ) {
    // check for validity
    checkPhrase(mnemonicPhrase)

    // calc seed
    var salt =  "mnemonic"
    if (password)
        salt += password
    return PBKDF2_512( hmac_sha512, mnemonicPhrase,  salt, 2048  )
}

/**
 *  check if a phrase is valid 
 * @param {string} mnemonicPhrase  UTF-8 NFKD phrase. ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
 * @param {boolean} ignoreCrc  if true, the fuction does not raise execption on crc errors
 * @return {boolean} true if <mnemonicPhrase> is valid. false if crc test fails and <ignoreCrc> is true
 * @throws {Error} if <mnemonicPhrase> is invalid
 */
function checkPhrase( mnemonicPhrase, ignoreCrc  )
{
    // split into words
    var tabWord = mnemonicPhrase.split(" ");
    // get number on bits in data and crc
    var nbWord = tabWord.length;
    var nbBitDataAndCrc = nbWord*11;
    var nbBitCrc  = 0;
    switch (nbWord) {
        case 12: nbBitCrc=4;console.assert(nbBitDataAndCrc-nbBitCrc == 128); break;
        case 15: nbBitCrc=5;console.assert(nbBitDataAndCrc-nbBitCrc == 160); break;
        case 18: nbBitCrc=6;console.assert(nbBitDataAndCrc-nbBitCrc == 192); break;
        case 21: nbBitCrc=7;console.assert(nbBitDataAndCrc-nbBitCrc == 224); break;        
        case 24: nbBitCrc=8;console.assert(nbBitDataAndCrc-nbBitCrc == 256); break;  
        default:
            throw _BuildError( LibErrors.Invalid_mnemonic_phrase_size, { mnemonicPhrase:mnemonicPhrase, nbWord:nbWord} ) 
    }
    var nbBitData = nbBitDataAndCrc-nbBitCrc;
    var nbByteData = nbBitData/8;
    // check each word and convert it to int
    tabIndex = []
    var numWord = 0;
    tabWord.forEach( word => {
       
        // thow an error if the index
        var index = 0;
        try {
          index = _getBip39IndiceFromWord( word )
        }
        catch (err) {
            // improve error message
            err.message = `Invalid word ${numWord+1} : ${word}.` 
            err.numWord = index
            throw err;
        }
        tabIndex.push( index );
        numWord++; 
    })
    // convert to buffer
    var buffer=""
    var index=0;
    for (var posBit=0;posBit<nbBitData+nbBitCrc;posBit+=11) {
        var value   = tabIndex[index]; // to be added in buffer
        buffer = _add11Bit( buffer, posBit, value);
        index++;
    }
    // calc CRC
    var maskBit = (0xFF << ( 8-nbBitCrc )) & 0xFF;
    var bufferData = buffer.substr( 0, nbByteData);
    var hash = sha256(bufferData)
    var crcCalc = hash.charCodeAt(0) & maskBit
    var crcData = buffer.charCodeAt(nbByteData) & maskBit
    // compare CRC
    if (crcCalc!=crcData) {
        if (ignoreCrc)
            return false;
        throw _BuildError( LibErrors.Invalid_mnemonic_phrase_crc, {crcCalc:crcCalc, crcData:crcData })
    }

    // Check OK
    return true;

//---------------------------
    // internal func : add 11 bits at pos <numBit> in buffer <buf>. 
    function _add11Bit( buf, numBit, value ) {
        var posInByte =  (numBit/8)>>>0
        // get current value
        var val32bit  = int32FromBigEndianBuffer(buf, posInByte )
        // add 11 bits
        var pos  = numBit % 8 
        val32bit = val32bit | (value << (32-11-pos))
        // calc final buffer
        buf = buf.substr(0,posInByte)
        buf += bigEndianBufferFromInt32(val32bit);
        return buf
    }
}

/**
 * get a list of all valid words to end a bip39 compatible phrase.
 * @param {string} incompletePhrase  phrase minus 1 word. ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front"
 * @return {Array.string} all valid  word.
 */
function getAllValidLastWord( incompletePhrase ) {
    // test if the beginning is correct
    checkPhrase( incompletePhrase + " " + getBip39WordFromIndice(0), true);

    var WordOK = []
    // test all 2048 possible words
    for (var i=0;i<2048;i++) {
        // word to test. ex "abandon"
        var wordI = getBip39WordFromIndice(i);
        // is the phare ok with this word ?
        var bWordOK =  checkPhrase( incompletePhrase + " " + wordI, true );
        if (bWordOK)
            WordOK.push(wordI);
    }
    console.assert( WordOK.length > 0 )
    return WordOK;
}

/**
 * convert a random buffer into a bip39 compatible phrase.
 * @param {string} randomBffer 128, 160,192,224 or 256 byte buffer
 * @return {string} mnemonic phrase. ex : "pistol thunder want public animal educate laundry all churn federal slab behind media front glow"
 * @throws {Error} if <randomBffer> is invalid
 */
function bip39phraseFromRandomBuffer( randomBffer ) {
    var nbBit = randomBffer.length*8
    console.assert( nbBit>=128 && nbBit <= 256, "invalid length" )
    // calc CRC
    var hash = sha256(randomBffer)
    var randomBufferAndCrc = randomBffer + hash.substr(0,1) 
    switch (nbBit) {
        case 128:    nbBit += 4;break;
        case 160:    nbBit += 5;break;
        case 192:    nbBit += 6;break;
        case 224:    nbBit += 7;break;
        case 256:    nbBit += 8;break;
        default: {
             throw _BuildError( LibErrors.Invalid_buffer_size,  {size:nbBit})
        }
    }
    // padding
    randomBufferAndCrc += '\x00'.repeat(3);

    // convert the  buffer to int
    var result = ""
    for (var posBit=0;posBit<nbBit;posBit+=11) {
        // get a 11 bit bloc at position
        var remBit  = posBit % 8;        
        var posByte = posBit >> 3;
        // get 32 bits
        var val32bit = int32FromBigEndianBuffer(randomBufferAndCrc, posByte )
        var mask     = 0xFFE00000 >>> remBit;   // ex: 0x7FF0
        var val11bit = (val32bit & mask) >>> (32-11-remBit);
        // get the word
        console.assert(val11bit >= 0 && val11bit < 2048);
        var wordI = getBip39WordFromIndice(  val11bit )
        // build phrase
        if (result!="") result += " ";
        result += wordI
    }

    return result
}

/**
 * 
 * PBKDF2 key derivation functions 
 * @see https://en.wikipedia.org/wiki/PBKDF2
 * @param {function} hashFunction * 
 * @param {string} password 
 * @param {string} salt 
 * @param {number} iteration 
 * @return {string} 512 bits buffer
 * 
 */
function PBKDF2_512( hashFunction, password, salt, iteration ) {
    // first iteration
    var U = hashFunction( password, salt + bigEndianBufferFromInt32( 1 )  )
    var F = U;
    for (var i=1;i<iteration;i++) {
        // next ieration 
        U = hashFunction( password, U )
        F = xorBuffer( F, U )
    }
    console.assert(F.length == 64, "T should be 512 bits")
    return F
}

function xorBuffer( buf1, buf2 ) {
    var res = ""
    for (var i=0;i<buf1.length;i++) {
        res += String.fromCharCode( buf1.charCodeAt(i) ^ buf2.charCodeAt(i) )
    }
    return res;
}
// 2048 english words 
// @see https://github.com/bitcoinjs/bip39/blob/master/src/wordlists/english.json
//      https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt
var WordList_english = [
     'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse','access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act','action','actor','actress','actual','adapt','add','addict','address','adjust','admit','adult','advance'
    ,'advice','aerobic','affair','afford','afraid','again','age','agent','agree','ahead','aim','air','airport','aisle','alarm','album','alcohol','alert','alien','all','alley','allow','almost','alone','alpha','already','also','alter','always','amateur','amazing','among'
    ,'amount','amused','analyst','anchor','ancient','anger','angle','angry','animal','ankle','announce','annual','another','answer','antenna','antique','anxiety','any','apart','apology','appear','apple','approve','april','arch','arctic','area','arena','argue','arm','armed','armor'
    ,'army','around','arrange','arrest','arrive','arrow','art','artefact','artist','artwork','ask','aspect','assault','asset','assist','assume','asthma','athlete','atom','attack','attend','attitude','attract','auction','audit','august','aunt','author','auto','autumn','average','avocado'
    ,'avoid','awake','aware','away','awesome','awful','awkward','axis','baby','bachelor','bacon','badge','bag','balance','balcony','ball','bamboo','banana','banner','bar','barely','bargain','barrel','base','basic','basket','battle','beach','bean','beauty','because','become'
    ,'beef','before','begin','behave','behind','believe','below','belt','bench','benefit','best','betray','better','between','beyond','bicycle','bid','bike','bind','biology','bird','birth','bitter','black','blade','blame','blanket','blast','bleak','bless','blind','blood'
    ,'blossom','blouse','blue','blur','blush','board','boat','body','boil','bomb','bone','bonus','book','boost','border','boring','borrow','boss','bottom','bounce','box','boy','bracket','brain','brand','brass','brave','bread','breeze','brick','bridge','brief'
    ,'bright','bring','brisk','broccoli','broken','bronze','broom','brother','brown','brush','bubble','buddy','budget','buffalo','build','bulb','bulk','bullet','bundle','bunker','burden','burger','burst','bus','business','busy','butter','buyer','buzz','cabbage','cabin','cable'
    ,'cactus','cage','cake','call','calm','camera','camp','can','canal','cancel','candy','cannon','canoe','canvas','canyon','capable','capital','captain','car','carbon','card','cargo','carpet','carry','cart','case','cash','casino','castle','casual','cat','catalog'
    ,'catch','category','cattle','caught','cause','caution','cave','ceiling','celery','cement','census','century','cereal','certain','chair','chalk','champion','change','chaos','chapter','charge','chase','chat','cheap','check','cheese','chef','cherry','chest','chicken','chief','child'
    ,'chimney','choice','choose','chronic','chuckle','chunk','churn','cigar','cinnamon','circle','citizen','city','civil','claim','clap','clarify','claw','clay','clean','clerk','clever','click','client','cliff','climb','clinic','clip','clock','clog','close','cloth','cloud'
    ,'clown','club','clump','cluster','clutch','coach','coast','coconut','code','coffee','coil','coin','collect','color','column','combine','come','comfort','comic','common','company','concert','conduct','confirm','congress','connect','consider','control','convince','cook','cool','copper'
    ,'copy','coral','core','corn','correct','cost','cotton','couch','country','couple','course','cousin','cover','coyote','crack','cradle','craft','cram','crane','crash','crater','crawl','crazy','cream','credit','creek','crew','cricket','crime','crisp','critic','crop'
    ,'cross','crouch','crowd','crucial','cruel','cruise','crumble','crunch','crush','cry','crystal','cube','culture','cup','cupboard','curious','current','curtain','curve','cushion','custom','cute','cycle','dad','damage','damp','dance','danger','daring','dash','daughter','dawn'
    ,'day','deal','debate','debris','decade','december','decide','decline','decorate','decrease','deer','defense','define','defy','degree','delay','deliver','demand','demise','denial','dentist','deny','depart','depend','deposit','depth','deputy','derive','describe','desert','design','desk'
    ,'despair','destroy','detail','detect','develop','device','devote','diagram','dial','diamond','diary','dice','diesel','diet','differ','digital','dignity','dilemma','dinner','dinosaur','direct','dirt','disagree','discover','disease','dish','dismiss','disorder','display','distance','divert','divide'
    ,'divorce','dizzy','doctor','document','dog','doll','dolphin','domain','donate','donkey','donor','door','dose','double','dove','draft','dragon','drama','drastic','draw','dream','dress','drift','drill','drink','drip','drive','drop','drum','dry','duck','dumb'
    ,'dune','during','dust','dutch','duty','dwarf','dynamic','eager','eagle','early','earn','earth','easily','east','easy','echo','ecology','economy','edge','edit','educate','effort','egg','eight','either','elbow','elder','electric','elegant','element','elephant','elevator'
    ,'elite','else','embark','embody','embrace','emerge','emotion','employ','empower','empty','enable','enact','end','endless','endorse','enemy','energy','enforce','engage','engine','enhance','enjoy','enlist','enough','enrich','enroll','ensure','enter','entire','entry','envelope','episode'
    ,'equal','equip','era','erase','erode','erosion','error','erupt','escape','essay','essence','estate','eternal','ethics','evidence','evil','evoke','evolve','exact','example','excess','exchange','excite','exclude','excuse','execute','exercise','exhaust','exhibit','exile','exist','exit'
    ,'exotic','expand','expect','expire','explain','expose','express','extend','extra','eye','eyebrow','fabric','face','faculty','fade','faint','faith','fall','false','fame','family','famous','fan','fancy','fantasy','farm','fashion','fat','fatal','father','fatigue','fault'
    ,'favorite','feature','february','federal','fee','feed','feel','female','fence','festival','fetch','fever','few','fiber','fiction','field','figure','file','film','filter','final','find','fine','finger','finish','fire','firm','first','fiscal','fish','fit','fitness'
    ,'fix','flag','flame','flash','flat','flavor','flee','flight','flip','float','flock','floor','flower','fluid','flush','fly','foam','focus','fog','foil','fold','follow','food','foot','force','forest','forget','fork','fortune','forum','forward','fossil'
    ,'foster','found','fox','fragile','frame','frequent','fresh','friend','fringe','frog','front','frost','frown','frozen','fruit','fuel','fun','funny','furnace','fury','future','gadget','gain','galaxy','gallery','game','gap','garage','garbage','garden','garlic','garment'
    ,'gas','gasp','gate','gather','gauge','gaze','general','genius','genre','gentle','genuine','gesture','ghost','giant','gift','giggle','ginger','giraffe','girl','give','glad','glance','glare','glass','glide','glimpse','globe','gloom','glory','glove','glow','glue'
    ,'goat','goddess','gold','good','goose','gorilla','gospel','gossip','govern','gown','grab','grace','grain','grant','grape','grass','gravity','great','green','grid','grief','grit','grocery','group','grow','grunt','guard','guess','guide','guilt','guitar','gun'
    ,'gym','habit','hair','half','hammer','hamster','hand','happy','harbor','hard','harsh','harvest','hat','have','hawk','hazard','head','health','heart','heavy','hedgehog','height','hello','helmet','help','hen','hero','hidden','high','hill','hint','hip'
    ,'hire','history','hobby','hockey','hold','hole','holiday','hollow','home','honey','hood','hope','horn','horror','horse','hospital','host','hotel','hour','hover','hub','huge','human','humble','humor','hundred','hungry','hunt','hurdle','hurry','hurt','husband'
    ,'hybrid','ice','icon','idea','identify','idle','ignore','ill','illegal','illness','image','imitate','immense','immune','impact','impose','improve','impulse','inch','include','income','increase','index','indicate','indoor','industry','infant','inflict','inform','inhale','inherit','initial'
    ,'inject','injury','inmate','inner','innocent','input','inquiry','insane','insect','inside','inspire','install','intact','interest','into','invest','invite','involve','iron','island','isolate','issue','item','ivory','jacket','jaguar','jar','jazz','jealous','jeans','jelly','jewel'
    ,'job','join','joke','journey','joy','judge','juice','jump','jungle','junior','junk','just','kangaroo','keen','keep','ketchup','key','kick','kid','kidney','kind','kingdom','kiss','kit','kitchen','kite','kitten','kiwi','knee','knife','knock','know'
    ,'lab','label','labor','ladder','lady','lake','lamp','language','laptop','large','later','latin','laugh','laundry','lava','law','lawn','lawsuit','layer','lazy','leader','leaf','learn','leave','lecture','left','leg','legal','legend','leisure','lemon','lend'
    ,'length','lens','leopard','lesson','letter','level','liar','liberty','library','license','life','lift','light','like','limb','limit','link','lion','liquid','list','little','live','lizard','load','loan','lobster','local','lock','logic','lonely','long','loop'
    ,'lottery','loud','lounge','love','loyal','lucky','luggage','lumber','lunar','lunch','luxury','lyrics','machine','mad','magic','magnet','maid','mail','main','major','make','mammal','man','manage','mandate','mango','mansion','manual','maple','marble','march','margin'
    ,'marine','market','marriage','mask','mass','master','match','material','math','matrix','matter','maximum','maze','meadow','mean','measure','meat','mechanic','medal','media','melody','melt','member','memory','mention','menu','mercy','merge','merit','merry','mesh','message'
    ,'metal','method','middle','midnight','milk','million','mimic','mind','minimum','minor','minute','miracle','mirror','misery','miss','mistake','mix','mixed','mixture','mobile','model','modify','mom','moment','monitor','monkey','monster','month','moon','moral','more','morning'
    ,'mosquito','mother','motion','motor','mountain','mouse','move','movie','much','muffin','mule','multiply','muscle','museum','mushroom','music','must','mutual','myself','mystery','myth','naive','name','napkin','narrow','nasty','nation','nature','near','neck','need','negative'
    ,'neglect','neither','nephew','nerve','nest','net','network','neutral','never','news','next','nice','night','noble','noise','nominee','noodle','normal','north','nose','notable','note','nothing','notice','novel','now','nuclear','number','nurse','nut','oak','obey'
    ,'object','oblige','obscure','observe','obtain','obvious','occur','ocean','october','odor','off','offer','office','often','oil','okay','old','olive','olympic','omit','once','one','onion','online','only','open','opera','opinion','oppose','option','orange','orbit'
    ,'orchard','order','ordinary','organ','orient','original','orphan','ostrich','other','outdoor','outer','output','outside','oval','oven','over','own','owner','oxygen','oyster','ozone','pact','paddle','page','pair','palace','palm','panda','panel','panic','panther','paper'
    ,'parade','parent','park','parrot','party','pass','patch','path','patient','patrol','pattern','pause','pave','payment','peace','peanut','pear','peasant','pelican','pen','penalty','pencil','people','pepper','perfect','permit','person','pet','phone','photo','phrase','physical'
    ,'piano','picnic','picture','piece','pig','pigeon','pill','pilot','pink','pioneer','pipe','pistol','pitch','pizza','place','planet','plastic','plate','play','please','pledge','pluck','plug','plunge','poem','poet','point','polar','pole','police','pond','pony'
    ,'pool','popular','portion','position','possible','post','potato','pottery','poverty','powder','power','practice','praise','predict','prefer','prepare','present','pretty','prevent','price','pride','primary','print','priority','prison','private','prize','problem','process','produce','profit','program'
    ,'project','promote','proof','property','prosper','protect','proud','provide','public','pudding','pull','pulp','pulse','pumpkin','punch','pupil','puppy','purchase','purity','purpose','purse','push','put','puzzle','pyramid','quality','quantum','quarter','question','quick','quit','quiz'
    ,'quote','rabbit','raccoon','race','rack','radar','radio','rail','rain','raise','rally','ramp','ranch','random','range','rapid','rare','rate','rather','raven','raw','razor','ready','real','reason','rebel','rebuild','recall','receive','recipe','record','recycle'
    ,'reduce','reflect','reform','refuse','region','regret','regular','reject','relax','release','relief','rely','remain','remember','remind','remove','render','renew','rent','reopen','repair','repeat','replace','report','require','rescue','resemble','resist','resource','response','result','retire'
    ,'retreat','return','reunion','reveal','review','reward','rhythm','rib','ribbon','rice','rich','ride','ridge','rifle','right','rigid','ring','riot','ripple','risk','ritual','rival','river','road','roast','robot','robust','rocket','romance','roof','rookie','room'
    ,'rose','rotate','rough','round','route','royal','rubber','rude','rug','rule','run','runway','rural','sad','saddle','sadness','safe','sail','salad','salmon','salon','salt','salute','same','sample','sand','satisfy','satoshi','sauce','sausage','save','say'
    ,'scale','scan','scare','scatter','scene','scheme','school','science','scissors','scorpion','scout','scrap','screen','script','scrub','sea','search','season','seat','second','secret','section','security','seed','seek','segment','select','sell','seminar','senior','sense','sentence'
    ,'series','service','session','settle','setup','seven','shadow','shaft','shallow','share','shed','shell','sheriff','shield','shift','shine','ship','shiver','shock','shoe','shoot','shop','short','shoulder','shove','shrimp','shrug','shuffle','shy','sibling','sick','side'
    ,'siege','sight','sign','silent','silk','silly','silver','similar','simple','since','sing','siren','sister','situate','six','size','skate','sketch','ski','skill','skin','skirt','skull','slab','slam','sleep','slender','slice','slide','slight','slim','slogan'
    ,'slot','slow','slush','small','smart','smile','smoke','smooth','snack','snake','snap','sniff','snow','soap','soccer','social','sock','soda','soft','solar','soldier','solid','solution','solve','someone','song','soon','sorry','sort','soul','sound','soup'
    ,'source','south','space','spare','spatial','spawn','speak','special','speed','spell','spend','sphere','spice','spider','spike','spin','spirit','split','spoil','sponsor','spoon','sport','spot','spray','spread','spring','spy','square','squeeze','squirrel','stable','stadium'
    ,'staff','stage','stairs','stamp','stand','start','state','stay','steak','steel','stem','step','stereo','stick','still','sting','stock','stomach','stone','stool','story','stove','strategy','street','strike','strong','struggle','student','stuff','stumble','style','subject'
    ,'submit','subway','success','such','sudden','suffer','sugar','suggest','suit','summer','sun','sunny','sunset','super','supply','supreme','sure','surface','surge','surprise','surround','survey','suspect','sustain','swallow','swamp','swap','swarm','swear','sweet','swift','swim'
    ,'swing','switch','sword','symbol','symptom','syrup','system','table','tackle','tag','tail','talent','talk','tank','tape','target','task','taste','tattoo','taxi','teach','team','tell','ten','tenant','tennis','tent','term','test','text','thank','that'
    ,'theme','then','theory','there','they','thing','this','thought','three','thrive','throw','thumb','thunder','ticket','tide','tiger','tilt','timber','time','tiny','tip','tired','tissue','title','toast','tobacco','today','toddler','toe','together','toilet','token'
    ,'tomato','tomorrow','tone','tongue','tonight','tool','tooth','top','topic','topple','torch','tornado','tortoise','toss','total','tourist','toward','tower','town','toy','track','trade','traffic','tragic','train','transfer','trap','trash','travel','tray','treat','tree'
    ,'trend','trial','tribe','trick','trigger','trim','trip','trophy','trouble','truck','true','truly','trumpet','trust','truth','try','tube','tuition','tumble','tuna','tunnel','turkey','turn','turtle','twelve','twenty','twice','twin','twist','two','type','typical'
    ,'ugly','umbrella','unable','unaware','uncle','uncover','under','undo','unfair','unfold','unhappy','uniform','unique','unit','universe','unknown','unlock','until','unusual','unveil','update','upgrade','uphold','upon','upper','upset','urban','urge','usage','use','used','useful'
    ,'useless','usual','utility','vacant','vacuum','vague','valid','valley','valve','van','vanish','vapor','various','vast','vault','vehicle','velvet','vendor','venture','venue','verb','verify','version','very','vessel','veteran','viable','vibrant','vicious','victory','video','view'
    ,'village','vintage','violin','virtual','virus','visa','visit','visual','vital','vivid','vocal','voice','void','volcano','volume','vote','voyage','wage','wagon','wait','walk','wall','walnut','want','warfare','warm','warrior','wash','wasp','waste','water','wave'
    ,'way','wealth','weapon','wear','weasel','weather','web','wedding','weekend','weird','welcome','west','wet','whale','what','wheat','wheel','when','where','whip','whisper','wide','width','wife','wild','will','win','window','wine','wing','wink','winner'
    ,'winter','wire','wisdom','wise','wish','witness','wolf','woman','wonder','wood','wool','word','work','world','worry','worth','wrap','wreck','wrestle','wrist','write','wrong','yard','year','yellow','you','young','youth','zebra','zero','zone','zoo' 
]
/**
 * get the full word list 
 * @return {arrya} an arary of 2048 english word
 */
 function getAllBip39Words() {
    return WordList_english   
}
/**
 * get a word in the list from index. 
 * @param {number} index  word number
 * @return {string} an english word. ex : "reward"
 */
function getBip39WordFromIndice( index ) {
    return WordList_english[index]     
}
/**
 * get a word index from its value 
 * @param {string} word an english word. ex : "reward"
 * @return {number} index. start at 0
 * @throws {Error} if <word> is invalid
 */
var wordToInt=[]; // global hash table
function _getBip39IndiceFromWord( word ) {
    // init at 1s call
    if (wordToInt.length==0) {
        for (var i=0;i<2048;i++)
        wordToInt[WordList_english[i]] = i;
    }
    // get index
    var index = wordToInt[word];
    if (index === undefined)  {
         throw _BuildError( LibErrors.Invalid_mnemonic_phrase_word, { word:word } );
    }
    return index;
}


