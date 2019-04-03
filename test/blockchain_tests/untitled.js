[
	"01111",
	"00000",
	"11100",
	"x0000",

]

'01111'=>[0,1,1,1,1];

function getBoardState(board) {
	const right = checkRight(board);
	if(!right) return 'error format';



}


function checkRight(board){

	let lengthArr=[];
	const boardLength = board && board.length;
	for (var i = board.length - 1; i >= 0; i--) {
		const element =board[i];
		if(i===board.length - 1){	lengthArr.push(element.length);}
		if(!element || element.length===0) return false;
		if(lengthArr.indexOf(element.length)===-1) return false;
		lengthArr.push(element.length);
	}



}


function checkWin(board){

	let count=0;
	for (var i = board.length - 1; i >= 0; i--) {
		const element=board[i];
		if(element){
			const elementArr= element.split();


			for (var i = elementArr.length - 1; i >= 0; i--) {
				const num=elementArr[i];
				if(num ==='x') return
				if(element.indexOf(num)!==-1 ) return
					count+=num;
			}
			if(count!==0 || count !==5) {count =0;}
			else{
				log('num为获胜者')
			}
		}
	}


}