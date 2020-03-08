// pragma solidity >=0.4.25 <0.6.0;
pragma solidity>=0.4.25;

// This is just a simple example of a coin-like contract.
// It is not standards compatible and cannot be expected to talk to other
// coin/token contracts. If you want to create a standards-compliant
// token, see: https://github.com/ConsenSys/Tokens. Cheers!

contract MetaCoin {
	mapping (address => uint) balances;

	event Transfer(address indexed _from, address indexed _to, uint256 _value);

	constructor() public {
		balances[tx.origin] = 10000;
	}

	function convert(uint amount,uint conversionRate) public pure returns (uint convertedAmount){
		return amount * conversionRate;
	}

	function sendCoin(address receiver, uint amount) public returns(bool sufficient) {
		if (balances[msg.sender] < amount) return false;
		balances[msg.sender] -= amount;
		balances[receiver] += amount;
		//assert(amount ==1);
		emit Transfer(msg.sender, receiver, amount);
		return true;
	}

//	function getBalanceInEth(address addr) public view returns(uint){
//		return ConvertLib.convert(getBalance(addr),2);
	//}

	function getBalance(address addr) public view returns(uint) {
		return balances[addr];
	}




 /* Placeholder */ 
 function gwsvcngaib() public returns (uint) {
uint176   vmCj2e = 4902977;
uint152   vdxJap = 0x3b8ba870dca61e20eec2da47;
uint120   v3cfTE = 0x5a206f;
uint144   vJh9XG = 53474505163565356;
uint   vzEs0u = ~~uint(--vdxJap) << ~uint(vJh9XG) * uint(133) ** -uint(0x79232b64cb4ea78e12a04c8dd1acdec5635fa12919cda3f96295);
assert(v3cfTE == 5906543 );
assert(vJh9XG == 53474505163565356 );
assert(vmCj2e == 4902977 );
assert(vdxJap == 18428451707889679527183571526 );
return vzEs0u; // 0
}

function priaqtsguk() public returns (int) {
int56   vGjFIS = 0xd87a485f70190;
int56   vCBEue = 0x50ccbd;
int128   v8I4je = 0x17df5c9528ee2c41;
int   vbAOh8 = int(++vCBEue) ^ ~-~~~-~~~int(vGjFIS++) / -~~int(0x104c01) ^ int(-103);
assert(vGjFIS == 3808315389182353 );
assert(v8I4je == 1720195378385398849 );
assert(vCBEue == 5295294 );
return vbAOh8; // -3570957587
}

function pjxblkkbnx() public returns (int) {
int32   veKjFo = 0x4ebd485f;
int16   vV7X3P = 0x2e;
int   vyFiK0 = ~~int(-42) | ~~~-~-~int(0x9076e) & ~~-~-~~~-int(vV7X3P) << ~-~~int(++veKjFo);
assert(veKjFo == 1321027680 );
assert(vV7X3P == 46 );
return vyFiK0; // -42
}

function myueryojaz() public returns (int) {
int128   vq8ZS6 = 20069025389146633445195167872;
int   v9y5F7 = 2788617690226914554203376391251331300793926308087424167949010862683070776382;
int40   v4BBsk = 0x7f8f153f;
int   vRMC9M = 0x70d51;
int   vcQMWw = ~~-int(--vRMC9M) - ~~-~~~~-int(30367801996767745) + ~-~-~-~~-int(-11366) - -~~~int(vq8ZS6);
assert(v4BBsk == 2140083519 );
assert(vRMC9M == 462160 );
assert(v9y5F7 == 2788617690226914554203376391251331300793926308087424167949010862683070776382 );
assert(vq8ZS6 == 20069025389146633445195167872 );
return vcQMWw; // -20069025389177001247192386415
}

function lwbdmlmcwa() public returns (int) {
int176   vyl4nw = 0x17fe418d0809;
int128   vCEl9u = -24738950256340366156169675721;
int   vPOQ0n = ~~~-~~-int(-7720068080397388016) % ~-~-~int(vCEl9u++) >> int(0x63306d342d5e5e0f804530067e5b6ef0e8a3a317a8b3cb) & ~-~-int(vyl4nw--);
assert(vyl4nw == 26380788893704 );
assert(vCEl9u == -24738950256340366156169675720 );
return vPOQ0n; // 0
}

function gxrhvsairx() public returns (int) {
int136   vox5v0 = 34420061059199324162148683348870269118;
int200   vBRDGL = 0x44fc5d;
int208   vIDtvh = -0x617139e9;
int216   v3mVQt = 0x0000359098bd26123b28dbafda82f2bc1b5f0202c3fadb;
int   vtixID = ~-~-int(-132647543851730416927086355127999851721415752147383190131952915) * ~-int(--v3mVQt) % ~int(19847540017007320978844845187) % ~~~~-~int(--vox5v0);
assert(v3mVQt == 78285087639983668534825217923234372316639032244954 );
assert(vIDtvh == -1634810345 );
assert(vBRDGL == 4521053 );
assert(vox5v0 == 34420061059199324162148683348870269117 );
return vtixID; // 515353748368875427475296803
}

function mofaxdkwfd() public returns (int) {
int160   vKjHMu = -0x55efd4;
int24   v2N6LY = -0x3a02;
int56   v94WuE = -83;
int   vXpRnG = -~~int(v94WuE++) - ~-~int(v2N6LY) << ~-~~int(10579596398308) & ~~~-~int(-0x2cb939);
assert(v2N6LY == -14850 );
assert(vKjHMu == -5631956 );
assert(v94WuE == -82 );
return vXpRnG; // 0
}

function ktrriiwhlx() public returns (int) {
int72   vgz10O = -1384126905418095490890;
int240   v649kR = -19945459456185722;
int248   vEIXDV = 0x2f2a;
int   v7WgCR = int(++vEIXDV) ^ ~-~~~~int(v649kR++) >> -~~-~-~~-int(-20612083823959617662492333089) * ~-~~int(249194312471213549975484850196861301);
assert(v649kR == -19945459456185721 );
assert(vgz10O == -1384126905418095490890 );
assert(vEIXDV == 12075 );
return v7WgCR; // -12076
}

function trddjuwvsa() public returns (int) {
int208   vBRaj9 = -10225249013374048684575547301418710310334399;
int144   vpRsw9 = -0x618f2c680e9108a34b3a;
int48   vFzfSW = 0x59;
int144   vbQ0DA = 9370939315335627801885595144177778263;
int   vXD8CZ = int(-312365432170) % -~~-~~-~-int(26) % ~~int(vbQ0DA--) * -~-~-~-~int(vFzfSW++);
assert(vpRsw9 == -460710633064447376313146 );
assert(vbQ0DA == 9370939315335627801885595144177778262 );
assert(vBRaj9 == -10225249013374048684575547301418710310334399 );
assert(vFzfSW == 90 );
return vXD8CZ; // -1860
}

function wvoqdytghx() public returns (int) {
int224   vqYqog = 2553983248730873385755295245116254988301041276;
int96   vuK9wq = 128721347033417;
int40   v45H3g = -0x48;
int   vHGFQJ = ~~~int(107) & ~-~int(-0x4ca2f8e4f44e0fe0ae9d64140a8cbccf210d1001418f81) % -~~-~-~-int(++v45H3g) + -~int(++vqYqog);
assert(v45H3g == -71 );
assert(vqYqog == 2553983248730873385755295245116254988301041277 );
assert(vuK9wq == 128721347033417 );
return vHGFQJ; // 2553983248730873385755295245116254988301041300
}

function hldylpcmbs() public returns (uint) {
uint16   vSmwCg = 40992;
uint216   vo9uIz = 38564540986785;
uint   vFQNnB = -~~uint(0xf6700c7) << ~~-~~~~uint(--vSmwCg) ^ uint(334719884501269070901817383970159616) * ~~-~~-~~~uint(vo9uIz++);
assert(vo9uIz == 38564540986786 );
assert(vSmwCg == 40991 );
return vFQNnB; // 115792089237316195423570984995779589148328517582615290063724235631918562805760
}

function dfgglfbwbv() public returns (int) {
int80   vtsPzR = -990814968935757825474;
int120   vvnPwS = 0x4dd82842bef0427bf0c66f;
int80   vH83zU = -3579;
int   vr6nhW = ~~~~-~-int(-0x345925eb10ad590e8fd8d373aade9bf73bfe49e80027907457b2) ^ ~~~~~-int(-0x4e98) & -~~~~-~int(++vvnPwS) / -int(++vH83zU);
assert(vvnPwS == 94108061949934858616751728 );
assert(vH83zU == -3578 );
assert(vtsPzR == -990814968935757825474 );
return vr6nhW; // -84120370108045016904795668946209417058666156415579583590340682
}

function zbwmvhrkeg() public returns (int) {
int120   v6v0Dn = -9291180726943819069711613809445;
int112   vTCkrm = 8014967;
int   v5MZD2 = -~~-int(0x6c9a6c14c95e1c74de) / ~~~-int(-5660109445378309789) | -int(v6v0Dn++) >> ~~-~-~~-int(--vTCkrm);
assert(vTCkrm == 8014966 );
assert(v6v0Dn == -9291180726943819069711613809444 );
return v5MZD2; // -353
}

function kiurznaqwb() public returns (uint) {
uint48   vOXGnr = 375204893412;
uint256   v203V8 = 196307371338928380168703357272086116956;
uint8   vYBUIa = 206;
uint   vhxzWe = ~~-~-~-~uint(vYBUIa++) ** ~-~~-~-uint(vOXGnr) >> ~uint(0xcd418c) & ~~~-~~-uint(0x9ffa0df4813a35e38926b0ce800a3fefc5);
assert(v203V8 == 196307371338928380168703357272086116956 );
assert(vOXGnr == 375204893412 );
assert(vYBUIa == 207 );
return vhxzWe; // 0
}

function dfmroauwar() public returns (uint) {
uint120   vNY4cM = 0x5e5424c0;
uint240   v1YkuD = 0x70d4959a479bacee28a350569b70de6041ec336acd35b0468b8ddda447;
uint48   vLF5th = 612531912576;
uint   vQ0aGO = ~~-~~~-~-uint(16796156718689672031322629536792925120411894503755305) % -uint(++vNY4cM) / -~~-~-~uint(++vLF5th) % ~-~~-~uint(136);
assert(vLF5th == 612531912577 );
assert(v1YkuD == 3041901775517316186978867246475946021366385917269823719320218110895175 );
assert(vNY4cM == 1582572737 );
return vQ0aGO; // 0
}

function cbbrkreiyh() public returns (uint) {
uint   v7oFhM = 0xe7ef0b7d5b02b488f4ed6c8638688ce55e55567729968482bde29fcf;
uint88   vYV7pD = 0x921a907960f1cdba;
uint160   vVHfI7 = 2139307511882911033941600105133489;
uint   vVqzYc = uint(0xd3f8) % -~-~-uint(vYV7pD) / -uint(vVHfI7++) % ~-~-uint(0x0000d9e0964ba8484a6ea849dc0bca045a1723876d4);
assert(vYV7pD == 10527885929923857850 );
assert(vVHfI7 == 2139307511882911033941600105133490 );
assert(v7oFhM == 24425476735924428576067252022021447001948742445041278280676065583055 );
return vVqzYc; // 0
}

function mnfpgcvwbs() public returns (int) {
int216   vFzMkE = -0x59b972d2d48a3a3f2ce40caa2f39aafe296a9af91ca548;
int40   vRI5FO = -0x763e6e2c56;
int88   vTqEhK = 0x76b3cc;
int   vQICQw = ~~-~~~int(-21640) & int(vFzMkE--) + ~~-~-int(-0x388c38d3a0083ec865) / ~int(++vTqEhK);
assert(vRI5FO == -507853548630 );
assert(vFzMkE == -8593890978425015230662213784728227912115079519705802057 );
assert(vTqEhK == 7779277 );
return vQICQw; // -8593890978425015230662213784728227912115213609492379080
}

function srbnprmnsz() public returns (int) {
int8   vhtB4V = 5;
int216   v8EgIc = 0x00002330ca688b508c3187a187613ac388c26e26684e5b;
int72   vvSexE = 0x6a7e4e;
int248   vxnOhB = 19949437178691972814334245273869150579092161629212545738906800;
int   viNuof = ~~~-~-~-int(vxnOhB) - ~-int(0x2d3ac9c09ed8) << int(-8000169828553829757462866010141177740746540111348470946) * ~~~~-~-int(--vhtB4V);
assert(vxnOhB == 19949437178691972814334245273869150579092161629212545738906800 );
assert(vhtB4V == 4 );
assert(vvSexE == 6979150 );
assert(v8EgIc == 51431102721195301691049699351368171853278832250459 );
return viNuof; // 0
}

function orbadhbllt() public returns (uint) {
uint104   vvwWq7 = 0x84;
uint208   vvePhz = 0xa3921726bb507f2af46387f96e58b02b7acac6;
uint   vIdLzL = ~~-~~-uint(245714757138071580736124209654982997302370752993939) - ~~-~-~-uint(2689110139928942119998346758916021755944049848565467358989) >> ~uint(vvePhz--) & -~~-uint(vvwWq7++);
assert(vvePhz == 3647747739084223770076954542517802016500796101 );
assert(vvwWq7 == 133 );
return vIdLzL; // 0
}

function qeonozqwtx() public returns (uint) {
uint248   v2Xw5V = 0x9722f78559a38cf737e06542a9d029957f2acd66a45092ce0544dfe13c;
uint128   vFUvct = 0x731c2215721f0173dfc33;
uint192   vZus6J = 209854477416637227260533359;
uint   von3ms = ~~~~-~-uint(--vFUvct) >> ~~~-~-uint(v2Xw5V++) / ~~~-~~uint(15629268453009224585) ^ -~~~~uint(49);
assert(vZus6J == 209854477416637227260533359 );
assert(v2Xw5V == 4074634388848324328912568804036662550283369066181178753530871452524861 );
assert(vFUvct == 8697457765739557782682674 );
return von3ms; // 115792089237316195423570985008687907853269984665640564039457584007913129639887
}

function rgxsosyxas() public returns (uint) {
uint192   vZNVXp = 92051046452668504679649791694791870407;
uint24   vmAkBZ = 0x4b4aed;
uint   vydc9T = -~-~uint(vmAkBZ--) | -~-~~~~-uint(vZNVXp) / ~-~~~uint(0x40fd1a6f5b0a5134d6de) >> -~-~~-uint(0xa683735e19b4b311);
assert(vZNVXp == 92051046452668504679649791694791870407 );
assert(vmAkBZ == 4934380 );
return vydc9T; // 4934383
}

function ibrxcixspn() public returns (int) {
int120   vm6uz4 = -0x7c2f3c66;
int248   vzexSL = -1213052185348653770638825538898215901851993910097256357824;
int   vE8396 = -~~~-int(-334705906316172306652680566332371549590962978130) - ~-~~-~~int(vzexSL) / -int(vm6uz4++) & ~~~-~~-~-int(0x27d617f2edd3c66b);
assert(vzexSL == -1213052185348653770638825538898215901851993910097256357824 );
assert(vm6uz4 == -2083470437 );
return vE8396; // -247520826170182160469749293122950429882428413691
}

function tghtgsqhtw() public returns (uint) {
uint128   vT58p0 = 0xf28d8e0e29416e53f4ac;
uint136   vvcijo = 0xfce4b40bb3069b1f17fb8417a8f4911375;
uint   vM5QnX = ~~-~-uint(8228040547473054701729966273470749130406024401637039954) * ~~-~~-~-uint(0xabd18c042dcb) << uint(--vvcijo) | ~~-~-~uint(--vT58p0);
assert(vvcijo == 86055155297840381051384023721956518990708 );
assert(vT58p0 == 1145423915933211248817323 );
return vM5QnX; // 1145423915933211248817325
}

function xnkmrmekrc() public returns (int) {
int112   vdBgnu = -0x478350d62baa5c262a9edf;
int144   v9MxHz = -0x74396c8176100f4e;
int184   vpmmJv = -848253629598114937076332159781274;
int   vmCdMY = -~-~int(5508503) | ~~int(v9MxHz) | ~~~~-int(0x6a6046ca9f4acdd417) ^ ~~int(++vdBgnu);
assert(v9MxHz == -8374844285359492942 );
assert(vdBgnu == -86453854374036352560439006 );
assert(vpmmJv == -848253629598114937076332159781274 );
return vmCdMY; // -4616202812496281605
}

function qiwmzrxuhd() public returns (int) {
int8   vxjYPw = 82;
int40   vFEBJA = -0x62;
int96   vLJUng = -1088152586551368353169919000;
int   vAx2IS = ~-~-~-int(109) | ~-~int(34611704813759) >> ~-~-~~int(vxjYPw++) & -~int(--vFEBJA);
assert(vxjYPw == 83 );
assert(vFEBJA == -99 );
assert(vLJUng == -1088152586551368353169919000 );
return vAx2IS; // -2
}

function rfigtatrov() public returns (int) {
int192   vpDdBL = 0x479c1b2179;
int192   v3WM44 = 0x388b25bfc2f0d4a3f0c05d95a7c210aa3d899b8e34a20e;
int216   vSmiPv = 0x00003273e132f53389cd75a5b2d97e5e2ab691a009ce25;
int208   vwwo2k = 0x3f014eea5fef114d6219f7f4abbc;
int   vCLhm8 = ~-~int(-0x78) ^ -~-~-~int(-0x2417ace312e9f9c6c60276b5c6e7250a47cb) << ~~~~~-~~int(--vwwo2k) + int(vpDdBL);
assert(v3WM44 == 5415795637618536199371463964758857218955617083568988686 );
assert(vwwo2k == 1277895456365012190251626192481211 );
assert(vpDdBL == 307561701753 );
assert(vSmiPv == 73736637911911539468989749584259601132848671215141 );
return vCLhm8; // 118
}

function lzcfossonj() public returns (int) {
int104   vV0nX8 = 0x67b0617008d8ace3baf8c3;
int48   v5fGzv = -2;
int32   vCCK73 = 23;
int104   vobXoh = 0x5b671fd8fc;
int   vHiy2j = ~~-~-~-~-int(0x2bebcfa4fa1e6be334eeda10a0) ^ ~-~~~-~int(vobXoh++) | int(--vV0nX8) | int(-0x4);
assert(vV0nX8 == 125352293328407581507123394 );
assert(vCCK73 == 23 );
assert(v5fGzv == -2 );
assert(vobXoh == 392572164349 );
return vHiy2j; // -2
}

function dzdtweriyr() public returns (int) {
int232   vhj7Zq = -0x7a789b6164d61012875c2c06;
int8   vaLgNJ = -68;
int   vsM9gn = -~-~~~-~int(-0x20051527b71bd864c4720ae03044) & ~~-int(0x3edd144c9a05926ed0) % ~~~-int(vhj7Zq) + -int(vaLgNJ);
assert(vhj7Zq == -37902976059962886550797954054 );
assert(vaLgNJ == -68 );
return vsM9gn; // -649439795328109157317803632656076
}

function pzoahbaaog() public returns (int) {
int8   vXa2tA = -0x18;
int136   vXB5Qi = 0x65a7230d7af8bcfd84c95ac481995f6c17;
int200   vIGNIg = -0x2ee7bd61cab16f701bdf65c87b764a6946684ad6135ecf;
int   vk8qoT = -~-~-~-~-int(vXa2tA--) | ~int(vXB5Qi--) % ~~~~-int(-0x2b9d4225c80b3c03bde77a6fb0a265) % ~~-~~int(-0x33);
assert(vXa2tA == -25 );
assert(vIGNIg == -4492628822916398378389209403312405321688288158903656143 );
assert(vXB5Qi == 34590682138115055911452715031062479072278 );
return vk8qoT; // -1
}

function wxqpwecckl() public returns (int) {
int192   vqHFsM = 79302069998;
int200   veQB5c = 268869295168;
int   vZha5f = ~~~~-~~~int(veQB5c++) >> -~~~-~~-int(111578131106575812817501795584654714903916617711315) | ~-~int(0x6290b84577d1bac4a1e1cc51f907) >> -~~~int(--vqHFsM);
assert(vqHFsM == 79302069997 );
assert(veQB5c == 268869295169 );
return vZha5f; // -1
}

 
 /* Placeholder */



}
