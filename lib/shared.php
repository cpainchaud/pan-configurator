<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud <cpainchaud _AT_ paloaltonetworks.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.

 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

set_time_limit ( 0 );
ini_set("memory_limit","14512M");
error_reporting(E_ALL);
gc_enable();

if (!extension_loaded('curl')) {
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        dl('php_curl.dll');
    } else {
        dl('curl.so');
    }
}


/**
*
* @ignore
*/
function show_backtrace($str)
{
  echo "\nBacktrace\n: $str";
  var_dump(debug_backtrace());
}

/**
*
* @ignore
*/
function memory_and_gc($str)
{
  $before = memory_get_usage(true);
  gc_enable();
  $gcs = gc_collect_cycles();
  $after = memory_get_usage(true);
  
  print "Memory usage at the $str : ".convert($before).". After GC: ".convert($after)." and freed $gcs variables\n";
}

function myErrorHandler($errno, $errstr, $errfile, $errline)
{
    if ($errno == E_USER_NOTICE || $errno == E_USER_WARNING || $errno == E_WARNING || $errno == E_NOTICE)
    {
        derr("Died on user notice or warning!! Error: {$errstr} on {$errfile}:{$errline}\n");
    }
    return false; //Will trigger PHP's default handler if reaches this point.
}


set_error_handler('myErrorHandler');

register_shutdown_function('my_shutdown');

// do some stuff
// ...


function my_shutdown()
{
	PH::$ignoreDestructors = true;
}


require_once dirname(__FILE__).'/misc-classes/'."trait-ReferenceableObject.php";
require_once dirname(__FILE__).'/misc-classes/'."trait-XmlConvertible.php";
require_once dirname(__FILE__).'/misc-classes/'."trait-ObjectWithDescription.php";
require_once dirname(__FILE__).'/misc-classes/'."class-DH.php";
require_once dirname(__FILE__).'/misc-classes/'."class-PH.php";
require_once dirname(__FILE__).'/misc-classes/'."class-RQuery.php";
require_once dirname(__FILE__).'/misc-classes/'."class-CsvParser.php";
require_once dirname(__FILE__).'/misc-classes/'."trait-PanSubHelperTrait.php";
require_once dirname(__FILE__).'/misc-classes/'."class-PanAPIConnector.php";

require_once dirname(__FILE__).'/container-classes/'."class-ObjRuleContainer.php";
require_once dirname(__FILE__).'/container-classes/'."class-ZoneRuleContainer.php";
require_once dirname(__FILE__).'/container-classes/'."class-TagRuleContainer.php";
require_once dirname(__FILE__).'/container-classes/'."class-AppRuleContainer.php";
require_once dirname(__FILE__).'/container-classes/'."class-AddressRuleContainer.php";
require_once dirname(__FILE__).'/container-classes/'."class-ServiceRuleContainer.php";

require_once dirname(__FILE__).'/object-classes/'."class-ObjStore.php";
require_once dirname(__FILE__).'/object-classes/'."class-TagStore.php";
require_once dirname(__FILE__).'/object-classes/'."class-AppStore.php";
require_once dirname(__FILE__).'/object-classes/'."class-AddressStore.php";
require_once dirname(__FILE__).'/object-classes/'."class-ServiceStore.php";
require_once dirname(__FILE__).'/object-classes/'."class-Tag.php";
require_once dirname(__FILE__).'/object-classes/'."class-App.php";
require_once dirname(__FILE__).'/object-classes/'."class-Address.php";
require_once dirname(__FILE__).'/object-classes/'."class-AddressGroup.php";
require_once dirname(__FILE__).'/object-classes/'."class-Service.php";
require_once dirname(__FILE__).'/object-classes/'."class-ServiceGroup.php";

require_once dirname(__FILE__).'/device-and-system-classes/'."class-VirtualSystem.php";
require_once dirname(__FILE__).'/device-and-system-classes/'."class-PANConf.php";
require_once dirname(__FILE__).'/device-and-system-classes/'."class-PanoramaConf.php";
require_once dirname(__FILE__).'/device-and-system-classes/'."class-DeviceGroup.php";
require_once dirname(__FILE__).'/device-and-system-classes/'."class-Template.php";
require_once dirname(__FILE__).'/device-and-system-classes/'."class-ManagedDevice.php";

require_once dirname(__FILE__).'/network-classes/'."class-Zone.php";
require_once dirname(__FILE__).'/network-classes/'."class-ZoneStore.php";
require_once dirname(__FILE__).'/network-classes/'."class-InterfaceContainer.php";
require_once dirname(__FILE__).'/network-classes/'."class-StaticRoute.php";
require_once dirname(__FILE__).'/network-classes/'."class-VirtualRouter.php";
require_once dirname(__FILE__).'/network-classes/'."class-VirtualRouterStore.php";
require_once dirname(__FILE__).'/network-classes/'."class-NetworkPropertiesContainer.php";
require_once dirname(__FILE__).'/network-classes/'."class-IPsecTunnelStore.php";
require_once dirname(__FILE__).'/network-classes/'."class-IPsecTunnel.php";
require_once dirname(__FILE__).'/network-classes/'."class-LoopbackIfStore.php";
require_once dirname(__FILE__).'/network-classes/'."class-LoopbackInterface.php";
require_once dirname(__FILE__).'/network-classes/'."class-EthernetInterface.php";
require_once dirname(__FILE__).'/network-classes/'."class-EthernetIfStore.php";
require_once dirname(__FILE__).'/network-classes/'."class-TmpInterface.php";
require_once dirname(__FILE__).'/network-classes/'."class-TmpInterfaceStore.php";
require_once dirname(__FILE__).'/network-classes/'."class-AggregateEthernetInterface.php";
require_once dirname(__FILE__).'/network-classes/'."class-AggregateEthernetIfStore.php";

require_once dirname(__FILE__).'/rule-classes/class-RuleStore.php';
require_once dirname(__FILE__).'/rule-classes/class-Rule.php';
require_once dirname(__FILE__).'/rule-classes/class-SecurityRule.php';
require_once dirname(__FILE__).'/rule-classes/class-NatRule.php';
require_once dirname(__FILE__).'/rule-classes/class-DecryptionRule.php';


function & array_diff_no_cast(&$ar1, &$ar2)
{
   $diff = Array();
   foreach ($ar1 as $key => $val1)
   {
      if (array_search($val1, $ar2, TRUE) === false)
      {
         $diff[$key] = $val1;
      }
   }
   return $diff;
}


function & array_unique_no_cast(&$ar1)
{
   $unique = Array();
   foreach ($ar1 as $val1)
   {
      if( array_search($val1, $unique, TRUE) === FALSE )
      	$unique[] = $val1;
   }

   return $unique;
}

/**
*
* @ignore
*/
function &searchForName($fname, $id, &$array)
  {
  	// $fname : is field name
  	// $id : the value you are looking for
  	$null = null;
  	
  	if( is_null($array) )
  		derr('Array cannot be null');
  	
  	$c = count($array);
  	$k = array_keys($array);
  	
  	  
	   for($i=0;$i<$c;$i++)
	   {
	       if ( isset($array[$k[$i]][$fname]) && $array[$k[$i]][$fname] === $id )
	       {
		   return $array[$i];
	       }
	   }
   return $null;

  }
  
  
/**
*
* @ignore
*/
 function &searchForNameAndAttribute($fname,$id, $attrid, $attrval, &$array)
  {
  	$c = count($array); 
  	$k = array_keys($array);
  	  
	   for($i=0;$i<$c;$i++)
	   {
	       if ($array[$k[$i]][$fname] === $id)
	       {
		   if( $array[$i]['attributes'][$attrid] === $attrval )
			return $array[$i];
	       }
	   }
	return null;
  }


/**
*
* @ignore
*/
function &attributes_to_str(&$attr)
{
	$out = '';
	
	$keys = array_keys($attr);
	
	$c = count($attr);
	
	for( $i=0; $i<$c; $i++ )
	{
		$out .= ' '.$keys[$i].'="'.$attr[$keys[$i]].'"';
	}
	//print_r($attr);
	
	return $out;
}

/**
*
* @ignore
*/
function &array_to_xml(&$x, $indenting = 0, $lineReturn = true)
{
	$ind = '';
	$out = '';
	
	for( $i=0; $i<$indenting; $i++ )
		$ind .= ' ';
	
	$firsttag = $ind.'<'.$x['name'];
	
	if( isset($x['attributes']) )
		$firsttag .= attributes_to_str($x['attributes']);
	
	//$firsttag .= '>';
	
	$c = 0;
	$wroteChildren = false;
	
	$tmpout = '';
	
	if( isset($x['children']) && count($x['children']) > 0 )
	{
		$c = count($x['children']);
		$k = array_keys($x['children']);

        foreach( $x['children'] as &$a )
		{
			if( $a['name'] == 'ignme' )
				continue;
			if( $indenting != -1 )
				$tmpout .= array_to_xml($a, $indenting + 1);
			else
				$tmpout .= array_to_xml($a, -1, $lineReturn);
			$wroteChildren = true;
		}
	}
	

		
	if( $wroteChildren == false )
	{

		if( !isset($x['content']) || strlen("".$x['content']) == 0 )
		{
			if( $lineReturn )
				$out .= $firsttag."/>\n";
			else
				$out .= $firsttag."/>";
		}
		else
		{
			if( $lineReturn )
				$out .= $firsttag.'>'.$x['content'].'</'.$x['name'].">\n";
			else
				$out .= $firsttag.'>'.$x['content'].'</'.$x['name'].">";
		}
	}
	else
	{
		if( $lineReturn )
			$out .= $firsttag.">\n".$tmpout.$ind.'</'.$x['name'].">\n";
		else
			$out .= $firsttag.">".$tmpout.$ind.'</'.$x['name'].">";
	}

	return $out;	
}


/**
*
* @ignore
*/
function clearA( &$a)
{
	if ( !is_array($a) )
	{
		derr("This is not an array\n");
	}
	$c = count($a);
	$k = array_keys($a);
	
	for($i=0; $i<$c; $i++ )
	{
		unset($a[$k[$i]]);
	}
}


/**
*
* @ignore
 * @param Array $a
 * @param ReferencableObject[]|string[] $objs
 * @param string $tagName
 * @param bool $showAnyIfZero
 * @param string $valueOfAny
*/
function Hosts_to_xmlA(&$a, &$objs, $tagName = 'member', $showAnyIfZero=true, $valueOfAny = 'any')
{
	//print_r($a);

	if( !is_array($a) )
		derr('only Array is accepted');
	
	$a = Array();
	
	$c = count($objs);
	if( $c == 0 && $showAnyIfZero)
	{
		$a[] = Array( 'name' => $tagName, 'content' => $valueOfAny );
		return;
	}

	foreach( $objs as $obj )
	{
		//print "doing '".$objs[$k[$i]]->name." out of i=$i'\n";
		$a[] = Array( 'name' => $tagName, 'content' => $obj->name());
	}
	//print_r($a);
}



function removeElement(&$o , &$arr)
{
	$pos = array_search( $o , $arr, TRUE );
	
	if( $pos === FALSE )
		return;
	
	unset($arr[$pos]);	
}


/**
* to be used only on array of objects
*
*/
function &insertAfter(&$arradd,&$refo,&$arr)
{
	$new = Array();
	
	$cadd = count($arradd);
	$kadd = array_keys($arradd);
	
	$c = count($arr);
	$k = array_keys($arr);
	
	for( $i=0; $i<$c; $i++ )
	{
		$new[] = &$arr[$k[$i]];
		
		if( $arr[$k[$i]] === $refo )
		{
			for( $iadd=0; $iadd<$cadd; $iadd++ )
			{
				$new[] = $arradd[$kadd[$iadd]]; 
			}
		}
	}
	
	return $new;
}
/**
*
* @ignore
 * @param ReferencableObject[] $arr
 *
*/
function reLinkObjs(&$arr, &$ref)
{
	$c = count($arr);
	$k = array_keys($arr);
	
	for( $i=0; $i<$c; $i++ )
	{
		$arr[$k[$i]]->addReference($ref);
	}
}

/**
*
* @ignore
*/
function addReference($o, $ref)
{
	if( is_null($ref) )
		return;
	
	$serial = spl_object_hash($ref);
	
	/*if( in_array($ref, $o->refrules, TRUE) )
	{
		//print "rule already referenced\n";
	}*/
	if( isset($o->refrules[$serial]) )
	{
		//print "rule already referenced\n";
	}
	else
	{
		$o->refrules[$serial] = $ref;
	}
}


/**
*
* @ignore
*/
function removeReference($o, $ref)
{
	if( is_null($ref) )
		return;
	
	$serial = spl_object_hash($ref);
	
	if( isset($o->refrules[$serial]) )
	{
		unset($o->refrules[$serial]);
	}
	else
	{
		mwarning('tried to unreference an object from a store that does not reference it:'.$o->toString().'  against  '.$ref->toString());
	}
}


/**
*
* @ignore
*/
class XmlArray {

  public function load_dom ($xml) {
    $node=simplexml_import_dom($xml);
    
    //print "Before node reading\n";
    
    return $this->add_node($node);
  }
  
  public function &load_string ($s) {
    $node=simplexml_load_string($s);
    //print "Before node reading\n";
    $ret = $this->add_node($node);
    return $ret;
  }
  
  private function add_node ($node, &$parent=null, $namespace='', $recursive=false) {
 
    $namespaces = $node->getNameSpaces(true);

    $r['name']=$node->getName();
    
    //$content="$node";
    $content=htmlspecialchars((string) $node);

    if ($namespace) $r['namespace']=$namespace;
    if (strlen($content)) $r['content']=$content;
    
    foreach ($namespaces as $pre=>$ns) {
      foreach ($node->children($ns) as $k=>$v) {
        $this->add_node($v, $r['children'], $pre, true);
      }
      foreach ($node->attributes($ns) as $k=>$v) {
        $r['attributes'][$k]="$pre:$v";
      }
    }
    foreach ($node->children() as $k=>$v) {
      $this->add_node($v, $r['children'], '', true);
    }
    foreach ($node->attributes() as $k=>$v) {
      $r['attributes'][$k]="$v";
    }
    
    $parent[]=&$r;
    return $parent[0];
    
  }
}


function convert($size)
 {
    $unit=array('b','kb','mb','gb','tb','pb');
    return @round($size/pow(1024,($i=floor(log($size,1024)))),2).' '.$unit[$i];
 }
 
 
function &cloneArray(&$old)
{
	$new = Array();
	
	$c = count($old);
	$k = array_keys($old);
	
	for( $i=0; $i<$c; $i++ )
	{
		if( is_array($old[$k[$i]]) )
		{
			if( isset( $old[$k[$i]]['name'] ) && $old[$k[$i]]['name'] == 'ignme' )
				continue;
			$new[$k[$i]] = cloneArray( $old[$k[$i]] );
		}
		else
			$new[$k[$i]] = $old[$k[$i]];
	}
	
	return $new;
}

function __CmpObjName( $objA, $objB)
{
	return strcmp($objA->name(), $objB->name());
}

function __CmpObjMemID( $objA, $objB)
{
	return strcmp(spl_object_hash($objA), spl_object_hash($objB));
}



/*function __RemoveObjectsFromArray( &$arrToRemove, &$originalArray)
{
	$indexes = Array();
	
	foreach( $originalArray as $i:$o )
	{
		//$indexes[spl_object_hash($o)] = $i;
	}
	
	
	unset($indexes);
}*/


trait PathableName
{
	/**
	*
	* @return String
	*/
	public function toString()
	{
		if( isset($this->name) )
			$ret = get_class($this).':'.$this->name;
		else
			$ret = get_class($this);
		
		if( isset($this->owner) && !is_null($this->owner) )
			$ret = $this->owner->toString().' / '.$ret;
			
		return $ret;
	}
	
}

function printn($msg)
{
	print $msg;
	print "\n";
}



function lastIndex(&$ar)
{
	end($ar);
	
	
	return key($ar);
}

/**
 * Stops script with an error message and a backtrace
 * @param string $msg error message to display
 * @param DOMNode $object
 * @throws Exception
 */
function derr($msg, $object=null)
{
    if( $object !== null )
    {
        $class = get_class($object);
        if( $class == 'DOMNode' || $class == 'DOMElement' || is_subclass_of($object, 'DOMNode') )
        {
            $msg .="\nXML line #".$object->getLineNo().", XPATH: ".DH::elementToPanXPath($object)."\n".DH::dom_to_xml($object,0,true,3);
        }
    }

	if( PH::$useExceptions )
	{
		$ex = new Exception($msg);
		throw $ex;
	}

    fwrite(STDERR,PH::boldText("\n* ** ERROR ** * ").$msg."\n\n");
	
	//debug_print_backtrace();
	
	$d = debug_backtrace() ;
	
	$skip = 0;
	
	fwrite(STDERR, " *** Backtrace ***\n");

    $count = 0;
	
	foreach( $d as $l )
	{
		if( $skip >= 0 )
        {
            print "$count ****\n";
			if( isset($l['object']) )
			{
				fwrite(STDERR,'   '.$l['object']->toString()."\n");
			}
			//print $l['function']."()\n";
			if( isset($l['object']) )
				fwrite(STDERR,'       '.PH::boldText($l['class'].'::'.$l['function']."()")." @\n           ".$l['file']." line ".$l['line']."\n");
			else
				fwrite(STDERR,'       ::'.$l['file']." line ".$l['line']."\n");
		}
		$skip++;
        $count++;
	}
	
	exit(1);
}

/**
* Prints a debug message along with a backtrace, program can continue normally.
*
*/
function mdeb($msg)
{
	global $PANC_DEBUG;

	if( !isset($PANC_DEBUG) || $PANC_DEBUG != 1 )
		return;

	print("\n*DEBUG*".$msg."\n");
	
	//debug_print_backtrace();
	
	$d = debug_backtrace() ;
	
	$skip = 0;
	
	fwrite(STDERR," *** Backtrace ***\n");
	
	foreach( $d as $l )
	{
		if( $skip >= 0 )
		{
			if( $skip == 0 && isset($l['object']) )
			{
				fwrite(STDERR,$l['object']->toString()."\n");
			}
			print $l['function']."()\n";
			if( isset($l['object']) )
				fwrite(STDERR,'       '.$l['class'].'::'.$l['file']." line ".$l['line']."\n");
			else
				fwrite(STDERR,'       ::'.$l['file']." line ".$l['line']."\n");
		}
		$skip++;
	}
	
	fwrite(STDERR,"\n\n");
}

function mwarning($msg, $object = null)
{
	global $PANC_WARN;

	if( isset($PANC_WARN) && $PANC_WARN == 0 )
		return;

	if( $object !== null )
	{
		$class = get_class($object);
		if( $class == 'DOMNode' || $class == 'DOMElement' || is_subclass_of($object, 'DOMNode') )
		{
			$msg .="\nXML line #".$object->getLineNo().", XPATH: ".DH::elementToPanXPath($object)."\nRaw xml:".DH::dom_to_xml($object,0,true,3);
		}
	}

	fwrite(STDERR,"\n*WARNING* ".$msg."\n");
	
	//debug_print_backtrace();
	
	$d = debug_backtrace() ;
	
	$skip = 0;
	
	print " *** Backtrace ***\n";
	
	foreach( $d as $l )
	{
		if( $skip >= 0 )
		{
			if( $skip == 0 && isset($l['object']) )
			{
				fwrite(STDERR,$l['object']->toString()."\n");
			}
			fwrite(STDERR,$l['function']."()\n");
			if( isset($l['object']) )
				fwrite(STDERR,'       '.$l['class'].'::'.$l['file']." line ".$l['line']."\n");
			else
				fwrite(STDERR,'       ::'.$l['file']." line ".$l['line']."\n");
		}
		$skip++;
	}
	
	fwrite(STDERR,"\n\n");
}


/**
*
* @ignore
*/
function boolYesNo($bool)
{
	static $yes = 'yes';
	static $no = 'no';
	
	if( $bool )
		return $yes;
	
	return $no;
}

function yesNoBool($yes)
{
	$yes = strtolower($yes);
	if($yes == 'yes' )
		return true;
	if( $yes == 'no' )
		return false;
	
	derr("unsupported value '$yes' given");
}

/**
 * @param $object
 * @return PanAPIConnector|null
 */
function findConnector( $object )
{
	if( isset($object->connector) )
		return $object->connector;

	if( !isset($object->owner) )
		return null;

	if( is_null($object->owner) )
		return null;

	return findConnector($object->owner);
}

function findConnectorOrDie( $object )
{
	if( isset($object->connector) )
		return $object->connector;

	if( !isset($object->owner) )
		derr("cannot find API connector");

	if( is_null($object->owner) )
		derr("cannot find API connector");

	return findConnector($object->owner);
}


function &array_to_devicequery(&$devices)
{
	$dvq = '';

	$first = true;

	foreach( $devices as &$device )
			{

				if( !$first )
					$dvq .= ' or ';

				$vsysl = '';

				$nfirst = true;
				foreach( $device['vsyslist'] as &$vsys)
				{
					if( !$nfirst )
						$vsysl .= ' or ';

					$vsysl .= "(vsys eq $vsys)";

					$nfirst = false;
				}

				$dvq .= " ((serial eq ".$device['serial'].") and ($vsysl)) ";

				$first = false;
			}

	return $dvq;
}

class cidr
{
    // convert cidr to netmask
    // e.g. 21 = 255.255.248.0
    static public function cidr2netmask($cidr)
    {
		$bin = '';

        for( $i = 1; $i <= 32; $i++ )
        $bin .= $cidr >= $i ? '1' : '0';

        $netmask = long2ip(bindec($bin));

        if ( $netmask == "0.0.0.0")
        return false;

    return $netmask;
    }

    // get network address from cidr subnet
    // e.g. 10.0.2.56/21 = 10.0.0.0
    static public function cidr2network($ip, $cidr)
    {
        $network = long2ip((ip2long($ip)) & ((-1 << (32 - (int)$cidr))));

    	return $network;
    }

    // convert netmask to cidr
    // e.g. 255.255.255.128 = 25
    static public function netmask2cidr($netmask)
    {
        $bits = 0;
        $netmask = explode(".", $netmask);

        foreach($netmask as $octect)
        $bits += strlen(str_replace("0", "", decbin($octect)));

    return $bits;
    }

    // is ip in subnet
    // e.g. is 10.5.21.30 in 10.5.16.0/20 == true
    //      is 192.168.50.2 in 192.168.30.0/23 == false 
    static public function cidr_match($ip, $network, $cidr)
    {
        if ((ip2long($ip) & ~((1 << (32 - $cidr)) - 1) ) == ip2long($network))
        {
            return true;
        }

    	return false;
    }

    /**
     * return 0 if not match, 1 if $sub is included in $ref, 2 if $sub is partially matched by $ref.
     * @param string|int[] $sub ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @param string|int[] $ref
     * @return int
     */
    static public function netMatch( $sub, $ref)
    {
        if( is_array($sub) )
        {
            $subNetwork = $sub['start'];
            $subBroadcast = $sub['end'];
        }
        else
        {
            $res = cidr::stringToStartEnd($sub);
            $subNetwork = $res['start'];
            $subBroadcast = $res['end'];
        }

        if( is_array($ref) )
        {
            $refNetwork = $ref['start'];
            $refBroadcast = $ref['end'];
        }
        else
        {
            $res = cidr::stringToStartEnd($ref);
            $refNetwork = $res['start'];
            $refBroadcast = $res['end'];
        }


    	if( $subNetwork >= $refNetwork && $subBroadcast <= $refBroadcast )
    	{
    		//print "sub $sub is included in $ref\n";
    		return 1;
    	}
    	if( $subNetwork >= $refNetwork &&  $subNetwork <= $refBroadcast || 
    		$subBroadcast >= $refNetwork && $subBroadcast <= $refBroadcast ||
    		$subNetwork <= $refNetwork && $subBroadcast >= $refBroadcast )
    	{
    		//print "sub $sub is partially included in $ref :  ".long2ip($subNetwork)."/".long2ip($subBroadcast)." vs ".long2ip($refNetwork)."/".long2ip($refBroadcast)."\n";
    		//print "sub $sub is partially included in $ref :  ".$refNetwork."/".$subBroadcast."/".$refBroadcast."\n";
    		return 2;
    	}

    	//print "sub $sub is not matching $ref :  ".long2ip($subNetwork)."/".long2ip($subBroadcast)." vs ".long2ip($refNetwork)."/".long2ip($refBroadcast)."\n";
    	return 0;
    }

    static public function & stringToStartEnd($value)
    {
        $result = Array();

        $ex = explode('-', $value);
        if( count($ex) == 2 )
        {
            if( filter_var($ex[0], FILTER_VALIDATE_IP) === false )
                derr("'{$ex[0]}' is not a valid IP");

            if( filter_var($ex[1], FILTER_VALIDATE_IP) === false )
                derr("'{$ex[1]}' is not a valid IP");

            $result['start'] = ip2long($ex[0]);
            $result['end'] = ip2long($ex[1]);
            return $result;
        }


        $ex = explode('/', $value);
        if( count($ex) > 1 && $ex[1] != '32')
        {
            //$netmask = cidr::cidr2netmask($ex[0]);
            if( $ex[1] < 0 || $ex[1] > 32 )
                derr("invalid netmask in value {$value}");

            if( filter_var($ex[0], FILTER_VALIDATE_IP) === false )
                derr("'{$ex[0]}' is not a valid IP");

            $bmask = 0;
            for($i=1; $i<= (32-$ex[1]); $i++)
                $bmask += pow(2, $i-1);

            $subNetwork = ip2long($ex[0]) & ((-1 << (32 - (int)$ex[1])) );
            $subBroadcast = ip2long($ex[0]) | $bmask;
        }
        elseif( count($ex) > 1 && $ex[1] == '32' )
        {
            if( filter_var($ex[0], FILTER_VALIDATE_IP) === false )
                derr("'{$ex[0]}' is not a valid IP");
            $subNetwork = ip2long($ex[0]);
            $subBroadcast = $subNetwork;
        }
        else
        {
            if( filter_var($value, FILTER_VALIDATE_IP) === false )
                derr("'{$value}' is not a valid IP");

            $subNetwork = ip2long($value);
            $subBroadcast = ip2long($value);
        }

        $result['start'] = $subNetwork;
        $result['end'] = $subBroadcast;

        return $result;
    }


}


function & sortArrayByStartValue( &$arrayToSort)
{
    //
    // Sort incl objects IP mappings by Start IP
    //
    //print "\n   * Sorting incl obj by StartIP\n";
    $returnMap = Array();
    $tmp = Array();
    foreach($arrayToSort as &$incl)
    {
        $tmp[] = $incl['start'];
    }
    unset($incl);
    sort($tmp, SORT_NUMERIC);
    foreach($tmp as &$value)
    {
        foreach($arrayToSort as &$incl)
        {
            if( $value == $incl['start'] )
            {
                //print "     -'".$incl['object']->name()." (".$incl['startip']."-".$incl['endip'].")'\n";
                $returnMap[] = $incl;
            }
        }
    }

    return $returnMap;
}

function & mergeOverlappingIP4Mapping( &$ip4mapping )
{
    $newMapping = sortArrayByStartValue($ip4mapping);

    $mapKeys = array_keys($newMapping);
    $mapCount = count($newMapping);
    for( $i=0; $i<$mapCount; $i++)
    {
        $current = &$newMapping[$mapKeys[$i]];
        //print "     - handling ".long2ip($current['start'])."-".long2ip($current['end'])."\n";
        for( $j=$i+1; $j<$mapCount; $j++)
        {
            $compare = &$newMapping[$mapKeys[$j]];
            //print "       - vs ".long2ip($compare['start'])."-".long2ip($compare['end'])."\n";

            if( $compare['start'] > $current['end'] + 1 )
                break;

            $current['end'] = $compare['end'];

            //print "             MERGED ->".long2ip($current['start'])."-".long2ip($current['end'])." \n";

            unset($newMapping[$mapKeys[$j]]);

            $i++;
        }
    }

    return $newMapping;
}

function removeNetworkFromIP4Mapping(&$targetMapping, &$zoneMapping)
{
    $affectedRows = 0;

    $arrayCopy = $targetMapping;
    $targetMapping = Array();

    foreach( $arrayCopy as &$entry )
    {
        if( $zoneMapping['start'] > $entry['end'] )
        {
            $targetMapping[] = &$entry;
            continue;
        }
        elseif( $zoneMapping['end'] < $entry['start'] )
        {
            $targetMapping[] = &$entry;
            continue;
        }
        else if( $zoneMapping['start'] <= $entry['start'] && $zoneMapping['end'] >= $entry['end'] )
        {

        }
        elseif( $zoneMapping['start'] > $entry['start'] )
        {
            if( $zoneMapping['end'] >= $entry['end'] )
            {
                $entry['end'] = $zoneMapping['start'] - 1;
                $targetMapping[] = &$entry;
            }
            else
            {
                $oldEnd = $entry['end'];
                $entry['end'] = $zoneMapping['start'] - 1;
                $targetMapping[] = &$entry;
                $targetMapping[] = Array('start'=> $zoneMapping['end']+1, 'end' => $oldEnd);
            }
        }
        else
        {
            $entry['start'] = $zoneMapping['end'] + 1;
            $targetMapping[] = &$entry;
        }
        $affectedRows++;
    }


    return $affectedRows;
}


class IP4Mapping
{

    /**
     * @param $mapping1
     * @param $mapping2
     * @return bool
     */
    public static function mapsAreEqual(&$mapping1, &$mapping2)
    {
        if( isset($mapping1['map']) )
            $ref1 = &$mapping1['map'];
        else
            $ref1 = &$mapping1;

        if( isset($mapping2['map']) )
            $ref2 = &$mapping2['map'];
        else
            $ref2 = &$mapping2;

        if( count($ref1) != count($ref2) )
            return false;

        $key1 = array_keys($ref1);
        $key2 = array_keys($ref2);


        for( $i=0; $i<count($key1); $i++)
        {
            if ($ref1[$key1[$i]]['start'] != $ref2[$key2[$i]]['start'] )
                return false;
            if ($ref1[$key1[$i]]['end'] != $ref2[$key2[$i]]['end'] )
                return false;
        }

        return true;
    }

    public static function IP4mapSubstraction( $referenceMap , &$substractedMap )
    {
        if( isset($referenceMap['map']) )
            $ref = &$referenceMap['map'];
        else
            $ref = &$referenceMap;

        if( isset($substractedMap['map']) )
            $sub = &$substractedMap['map'];
        else
            $sub = &$substractedMap;


        foreach( $sub as &$ip4map )
        {
            removeNetworkFromIP4Mapping($ref, $ip4map );
            if( count($ref) == 0 )
                break;
        }

        return $referenceMap;
    }

    public static function & IP4mapDiff( $referenceMap , $substractedMap )
    {
        if( isset($referenceMap['map']) )
            $ref = &$referenceMap['map'];
        else
            $ref = &$referenceMap;

        if( isset($substractedMap['map']) )
            $sub = &$substractedMap['map'];
        else
            $sub = &$substractedMap;


        $diff = Array();

        $diff['plus'] = IP4Mapping::IP4mapSubstraction($ref, $sub);
        $diff['minus'] = IP4Mapping::IP4mapSubstraction( $sub, $ref);

        return $diff;
    }

}




