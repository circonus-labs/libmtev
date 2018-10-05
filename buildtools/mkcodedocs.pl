#!/usr/bin/perl

use strict;
use File::Find;
use Data::Dumper;
my $inbase = shift || die;
my $outdir = shift || die;
my %docs;

my $uk = 0;
my $MAXLINE=79;

my $parts = {
  'md' => 'notes',
  'fn' => 'c',
  'var' => 'c',
  'lua' => 'lua'
};

sub mtevcmp {
  (my $ls = $a) =~ s/^mtev[\._]//i;
  (my $rs = $b) =~ s/^mtev[\._]//i;
  return lc($ls) cmp lc($rs);
}
sub fn_format {
  my $type = shift;
  my $ret = shift;
  my $fn = shift;
  my $param = shift;
  $param =~ s/[\n\s]+/ /gsm;
  my $len = length("$fn");
  my @p = split /\s*,\s*/, $param;
  my $seg = "";
  my $lead = "";
  my $lang = "";
  $lang = "c" if ($type eq 'fn');
  $lang = "c" if ($type eq 'var');
  $lang = "lua" if ($type eq 'lua');

  my $form = "```$lang\n";
  $form .= "$ret\n" if($ret);
  $form .= "$fn";
  while(scalar(@p) > 0) {
    if((length($seg) + 2 + length($p[0])) < $MAXLINE) {
      if(length($seg)) { $seg = "$seg, $p[0]"; }
      else { $seg = "$p[0]"; }
      shift(@p);
    }
    else {
      my $trail = (scalar(@p) == 1) ? "" : ", ";
      if(length($seg)) { $form .= "$lead$seg$trail\n"; $lead = " " x ($len+1); $seg = ""; }
      else {
        $form .= "$lead$p[0]$trail\n";
        $lead = " " x ($len+1);
        shift @p;
      }
    }
  }
  if(length($seg)) { $form .= "$lead$seg\n"; }
  $form .= "```\n";
  return $form;
}
sub format_md {
  my $type = shift;
  my $in = shift;
  my $dtype;
  my $func = "anon_$uk"; $uk++;
  if($type eq 'md') {
    $in =~ s/^.*$//;
    return ($func, $in);
  }

  if($in =~ /\\(var|fn|lua)\s*(.*?)([a-zA-Z\._][a-zA-Z0-9:\._]*)\s*(?:\(|\n)/) {
    $dtype = $1;
    $func = $3;
  }

  $in =~ s/^[ \t]*//g;

  $in =~ s/\\(var)\s*([^\n]*?)([a-zA-Z\._][a-zA-Z0-9:\._]*)()[ \t]*\n\\brief\s+([^\n]*)
          /sprintf("#### %s\n\n>%s\n\n%s\n", $3, $5, fn_format($1,$2,$3,$4));/xesg;
  $in =~ s/\\(fn|lua)\s*(.*?)([a-zA-Z\._][a-zA-Z0-9:\._]*)(\(.*?\))\n\\brief\s+([^\n]*)
          /sprintf("#### %s\n\n>%s\n\n%s\n", $3, $5, fn_format($1,$2,$3,$4));/xesg;
  $in =~ s/\\(fn|lua)\s*(.*?)([a-zA-Z\._][a-zA-Z0-9:\._]*)(\(.*?\))\n
          /sprintf("#### %s\n\n%s\n", $3, fn_format($1,$2,$3,$4));/xeg;
  $in =~ s/\\brief\s+(.*)/\n> $1\n\n/g;
  $in =~ s/\\param\s+(\S+)\s(.*)/  * `$1` $2/g;
  $in =~ s/\\return\s+(.*)/  * **RETURN** $1/g;

  # remove all trailing whitespace
  $in =~ s/[ \t]+\n/\n/gsm;

  return ($func, "$in\n\n");
}

sub xlate {
  my $in = shift;
  open(F, "<$in") || die " <<< $in ";
  $/ = undef;
  my $a = <F>;
  close(F);
  # remove leading "--" in lua files
  if ($in =~ /.lua$/) {
      $a =~ s/^--+//gm;
  }
  while($a =~ /\/\*!\s+(\\(md|var|fn|lua).*?)\*\//smg) {
    my $type = $2;
    my $b = $1;
    $b =~ s/^(?:\t| {4})//gm;
    my $func;
    ($func, $b) = format_md($type, $b);
    my $part = $parts->{$type} || "notes";
    $docs{$part} ||= {};
    $docs{$part}->{$func} = $b;
  }
  return 1;
}

finddepth({
  untaint => 1,
  wanted => sub {
    (my $file = $File::Find::name) =~ s/^$inbase\///;
    return 1 if -d $File::Find::name;
    return if($file !~ /\.(?:c|h|lua|java)$/);
    (my $out = $file) =~ s/(\/|\.)/_/g;
    ### Specific to libmtev
    $out =~ s/^utils_//g;
    xlate("$inbase/$file");
  },
  no_chdir => 1
}, $inbase);


my $idx = {};
for my $part (keys %docs) {
  my $pname = $part;
  open(F, ">$outdir/$pname.md");
  my $lt = "";
  for my $func (sort mtevcmp keys %{$docs{$part}}) {
    (my $afunc = $func) =~ s/^mtev[\._]//;
    if (lc(substr($afunc,0,1)) ne lc($lt)) {
      ($lt = substr($afunc,0,1)) =~ tr/[a-z]/[A-Z]/;
      print F "### $lt\n\n"
    }
    $idx->{$pname} ||= {};
    $idx->{$pname}->{$lt} ||= [];
    push @{$idx->{$pname}->{$lt}}, $func;
    print F $docs{$part}->{$func};
  }
  close(F);
}

open(F, ">$outdir/README.md");
print F "# Programmer's Reference Manual\n\n";
for my $pname (sort keys %$idx) {
  print F "## " . ucfirst($pname) . "\n\n";
  for my $lt (sort keys %{$idx->{$pname}}) {
    print F "##### " . uc($lt) . "\n\n";
    my $sep = "";
    for my $func (@{$idx->{$pname}->{$lt}}) {
       (my $anchor = $func) =~ s/[._]//g;
       printf F "%s[%s](%s.md#%s)", $sep, $func, $pname, $anchor;
       $sep = ", ";
    }
    print F "\n\n";
  }
}
close(F);
