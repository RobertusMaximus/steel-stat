#  Statistics file
#  Rewritten by Robert Day CISSP 2/16/2012
#
#   file : statsv20.pl
#
#   function : Create a stats file
#
#   part of : N/A
#
#
#
#
##############################################

#!/usr/bin/perl

# vars
my $filedir = "/var/log/stats.txt";
my $logdir = "/var/log/snort";
my $alert = "/var/log/snort/alert";
my $snortlog;
my $virus = "/opt/mwg/log/user-defined-logs/foundViruses.log";
my $tmp1;
my $tmp2;
my $tmp3;
my $tmp4;
my $tmpfile1;
my $tmpfile2;
my $tmpfile3;
my $tmpfile4;
my $fqdn;
my $uptimed;
my $file;
my @filecontents;
my $filedir_argv;
my $search1;
my $searchcnt1 = "0";
my $year1;
my $month1;
my $day1;
my @stat1;
my @stat2;
my @stat3;
my @stat4;
my @stat5;
my @stat5;

# tools
my $mv = "/bin/mv";
my $cat = "/bin/cat";
my $da = "/bin/date";
my $up = "/usr/bin/uptime";
my $hostname = "/bin/hostname";
my $wc = "/usr/bin/wc -l";
my $grep = "/bin/grep -i";

# Program

main();


sub main{
	$filedir_argv = $ARGV[0];
	chomp $filedir_argv; 
	$search1 = $ARGV[1];
	chomp $search1;
	datetime();
	name();
	#up();
	actions();
	testprint();
	#writefile();
	};

sub datetime{
        $tmp1=`date +%H:%M`;
        chomp $tmp1;
        $tmp2=`date +%m.%d.%y`;
        chomp $tmp2;
	$year1=`date +%y`;
	chomp $year1;
	$month1=`date +%m`;
	chomp $month;
	$day1=`date +%d`;
	chomp $day1;
	
        };

sub name{
  	$fqdn = `$hostname`;
  	chomp $fqdn;
	};

sub up{
  	$uptimed = `$up`;
  	chomp $uptimed;
	};

sub actions{
	if($filedir_argv eq "snort"){
		my @filelist = glob ("$access/access*");
		while(@filelist){
			my $cnt = @filelist;
			chomp $cnt;
			my $name = shift @filelist;
			chomp $name;
			#read the file
			system("cd $access");
			open(FILE3, "< $name") or die "$name file is missing from the working directory!\n";    
			@filecontent2 = <FILE3>;
			close(FILE3);
			#sort - reverse the line order
			@filecontent3 = sort {$b cmp $a}@filecontent2;
			#evaluate the lines
			while(@filecontent3){
				my $cnt2 = @filecontent3;
				chomp $cnt2;
				my $logline1 = shift @filecontent3;
				chomp $logline1;
				$_ = $logline1;
				my @result1 = split ('] | "|" |" "| (|)"'); #split each line up
				my @resultv2 = grep { defined $_ } @result1; # stip out the nulls
				#@resultsort1 = sort {$b cmp $a} @resultv2; #reverse the order
				while(@resultv2){
					my $word1 = shift @resultv2;
					chomp $word1;
					$_ = $word1;
					s/"//g;
					s/\[//g;
					s/\]//g;
					s/\(//g;
					s/\)//g;
					$word1 = $_;
					#print("WORD: $word1\n");
					$_ = $word1;
					if(m/$search1/g){
							++$searchcnt1;
							chomp $searchcnt1;
							#print("Word Count: $searchcnt1\n");
						}else{
							#dump data
							};
					#@stat1
				};
				#$_ = $logline1;
				#my @result2 = split (' ');
				#@resultsort2 = sort @result2;
				#while(@resultsort2){
				#	my $word2 = shift @resultsort2;
				#	chomp $word2;
				#	print("WORD: $word2\n");
					#@stat2
				#};				
			};
			#print("Access Count; $cnt path: $name\n");
			
	
		};
	}elsif($filedir_argv eq "alert"){
		my @filelist = glob ("$alert/access*");
		while(@filelist){
			my $cnt = @filelist;
			chomp $cnt;
			my $name = shift @filelist;
			chomp $name;
			#read the file
			system("cd $alert ");
			open(FILE3, "< $name") or die "$name file is missing from the working directory!\n";    
			@filecontent2 = <FILE3>;
			close(FILE3);
			#sort - reverse the line order
			@filecontent3 = sort {$b cmp $a}@filecontent2;
			#evaluate the lines
			while(@filecontent3){
				my $cnt2 = @filecontent3;
				chomp $cnt2;
				my $logline1 = shift @filecontent3;
				chomp $logline1;
				$_ = $logline1;
				my @result1 = split (' "|" |" "'); #split each line up
				my @resultv2 = grep { defined $_ } @result1; # strips out the nulls (undefined array elements versus defined elements of the arrray)
				#@resultsort1 = sort {$b cmp $a} @resultv2; #reverse the order
				my @data1 = @resultv2;
				while(@resultv2){
					my $word1 = shift @resultv2;
					chomp $word1;
					$_ = $word1;
					s/"//g;
					s/ "//g;
					$word1 = $_;
					$_ = $word1;
					if(m/$search1/g){
							++$searchcnt1;
							chomp $searchcnt1;
							#print("Word: $word1 Count:$searchcnt1\n");
							print("ARRAY-Element-0: $data1[0]\n");
							print("ARRAY-Element-1: $data1[1]\n");
							#print("ARRAY-Element-2: $data1[2]\n");
							print("ARRAY-Element-3: $data1[3]\n");
							print("ARRAY-Element-4: $data1[4]\n");
							print("ARRAY-Element-4: $data1[5]\n");
							chomp $datactr1;
							#print("DATA CTR1: @data1\n");
						}else{
							#dump data
							};
					#@stat1
				};
				#$_ = $logline1;
				#my @result2 = split (' ');
				#@resultsort2 = sort @result2;
				#while(@resultsort2){
				#	my $word2 = shift @resultsort2;
				#	chomp $word2;
				#	print("WORD: $word2\n");
					#@stat2
				#};				
			};
			#print("Access Count; $cnt path: $name\n");	
		};
	
	
	}else{
			print("\n");
			print("-----------------------------\n");
			print("The command line to use is:\n");
			print("-----------------------------\n");	
			print("perl statsv3.pl alert seachword\n");
			print("or\n");
			print("perl statsv3.pl snort seachword\n");
			print("-----------------------------\n");
			print("\n");
	};
};

sub fileload{
  open(FILE2, "< ./$file") or die "$file file is missing from the working directory!\n";    
  @filecontents = <FILE2>;
  close(FILE2);
};

sub testprint{
	if($searchcnt1 gt "0"){
		print("Final $search1 Count: $searchcnt1\n")
		};
	};
sub writefile{
        open(FILE1, ">> $filedir");
        #print FILE1 "\n";
        print FILE1 "-----------\n";
        print FILE1 " Time: $tmp1\n";
        print FILE1 " Date: $tmp2\n";   
        print FILE1 " Hostname: $fqdn\n";
        print FILE1 "$uptimed\n";
        print FILE1 "-----------\n";
        #print FILE1 "\n";  
        close(FILE1);
	};