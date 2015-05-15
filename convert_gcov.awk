/gcov_dump/ {
	init = 1;
	tstr="";
	next;
}

!/gcda/ {
	tstr = tstr""$0;
	next;
}

/gcda/ {
	if (!init) { 
		next;
	}
	print tstr > $0".xxd";
	tstr=""
	next;
}
