#!/usr/bin/perl

use strict;
use DBI;
my $dbh = DBI->connect("dbi:SQLite:dbname=hlr.sqlite3","","");


my %mcc_names;
my %mcc_mnc_names;

sub get_mcc_mnc_name($)
{
	my $mcc_mnc = shift;
	my $ret = $mcc_mnc;

	if ($mcc_mnc_names{$mcc_mnc} ne '') {
		$ret = $mcc_mnc_names{$mcc_mnc};
	}

	return $ret;
}

sub read_networks($)
{
	my $filename = shift;
	my $cur_name;

	open(INFILE, $filename);
	while (my $l = <INFILE>) {
		chomp($l);
		if ($l =~ /^#/) {
			next;
		}
		if ($l =~ /^\t/) {
			my ($mcc, $mnc, $brand, $r) = split(' ', $l, 4);
			#printf("%s|%s|%s\n", $mcc, $mnc, $brand);
			$mcc_mnc_names{"$mcc-$mnc"} = $brand;
			$mcc_names{$mcc} = $cur_name;
		} elsif ($l =~ /^(\w\w)\t(.*)/) {
			#printf("%s|%s\n", $1, $2);
			$cur_name = $2;
		}
	}
	close(INFILE);
}

read_networks("networks.tab");

my %oper_count;
my %country_count;

#my $sth = $dbh->prepare("SELECT imsi FROM subscriber where authorized=1");
my $sth = $dbh->prepare("SELECT imsi FROM subscriber");

$sth->execute();

while (my $href = $sth->fetchrow_hashref) {
	my ($mcc, $mnc) = $$href{imsi} =~ /(\d{3})(\d{2}).*/;
	#printf("%s %s-%s \n", $$href{imsi}, $mcc, $mnc);
	$oper_count{"$mcc-$mnc"}++;
	$country_count{$mcc}++;
}


foreach my $c (sort{$country_count{$b} <=> $country_count{$a}} keys %country_count) {
	printf("%s: %d\n", $mcc_names{$c}, $country_count{$c});

	foreach my $k (sort{$oper_count{$b} <=> $oper_count{$a}} keys %oper_count) {
		if ($k =~ /^$c-/) {
			printf("\t%s: %d\n", get_mcc_mnc_name($k), $oper_count{$k});
		}
	}
}
