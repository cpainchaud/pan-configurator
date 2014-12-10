<?php

/******************************************************************************
*
*	author: Christophe Painchaud (cpainchaud@palolaltonetworks.com)
*   (c) Palo Alto Networks
*
*    latest version can be found at https://live.paloaltonetworks.com/docs/DOC-7421
*
******************************************************************************/


set_time_limit ( 0 );
ini_set("memory_limit","5512M");
error_reporting(E_ALL);

if( $argc != 5 )
	die("usage: php $argv[0] host user password location/group\nExample: php $argv[0] 10.0.0.2 admin mypasswd shared/group1\n\n");

$rgroup = explode('/', $argv[4]);

if( count($rgroup) != 2 )
	die("invalid group location/name : $argv[4]\n\n");

$requestSubSystem = $rgroup[0];
$requestGroup = $rgroup[1];


function derr($msg)
{
	print("\n* ** ERROR ** * ".$msg."\n\n");
	
	//debug_print_backtrace();
	
	$d = debug_backtrace() ;
	
	$skip = 0;
	
	fwrite(STDERR, " *** Backtrace ***\n");
	
	foreach( $d as $l )
	{
		if( $skip >= 0 )
		{
			if( isset($l['object']) )
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
	
	die();
}

class PanAPIConnector
{
    public $name = 'connector';
	
	public $apikey;
	public $apihost;
	public $isPANOS = 1;

    protected $showApiCalls=false;

    static private $savedConnectors = Array();
    static private $keystorefilename = '.panconfkeystore';

    static public function loadConnectorsFromUserHome()
    {
        $file = getenv('HOME').'/'.self::$keystorefilename;
        if( file_exists($file) )
        {
            $content = file_get_contents($file);
            $content = explode("\n", $content);
            foreach( $content as &$line )
            {
                $parts = explode(',', $line);
                if( count($parts) != 3 )
                    continue;
                if( $parts[2] != 'panos' && $parts[2] != 'panorama' && $parts[2] != 'panos-via-panorama')
                    continue;
                self::$savedConnectors[] = new PanAPIConnector($parts[0],$parts[2],$parts[1]);
            }
        }
    }

    static public function saveConnectorsToUserHome()
    {
        $content = '';
        foreach( self::$savedConnectors as $conn )
        {

        }
    }

	
	public function toString()
	{
		return get_class($this).':'.$this->apihost;
	}

    public function setShowApiCalls($yes)
    {
        $this->showApiCalls = $yes;
    }
	
	public function PanAPIConnector( $host, $key, $type = 'panos', $serial = null)
	{
		$type = strtolower($type);
		if( $type == 'panos' )
			$this->isPANOS = 1;
		else if( $type == 'panorama' )
			$this->isPANOS = 0;
        else if( $type == 'panos-via-panorama')
            $this->serial = $serial;
		else
			derr('This is not supported type: '.$type);
		
		$this->apikey = $key;
		$this->apihost = $host;
	}
	
	public function & sendRequest($url, $checkResultTag=false, &$filecontent=null, $filename = '')
	{
        $url = str_replace('#', '%23',$url);

		
        if( isset($this->serial) && !is_null($this->serial) )
            $url = 'https://'.$this->apihost.'/api/?key='.$this->apikey.'&target='.$this->serial.'&'.$url;
        else
            $url = 'https://'.$this->apihost.'/api/?key='.$this->apikey.'&'.$url;

        if( $this->showApiCalls )
        {
            print("API call: \"".$url."\"\r\n");
        }

		$c = new mycurl($url);

        if( !is_null($filecontent) )
        {
            $c->setInfile($filecontent, $filename);
        }


		if( ! $c->createCurl() )
		{
			derr('Could not retrieve URL: '.$url.' because of the following error: '.$c->last_error);
		}
		
		$xmlobj = new XmlArray();

        if( $c->getHttpStatus() != 200 )
        {
            derr('HTTP API ret: '.$c->__tostring());
        }
				
		$xmlarr = $xmlobj->load_string($c->__tostring());
		
		if( ! is_array($xmlarr) )
		{
			derr('API didnt return a XML string: '.$c->__tostring());
		}
		
		if( !isset( $xmlarr['attributes']['status']) )
		{
			derr('XML response has no "status" field: '.array_to_xml($xmlarr));
		}
		
		if( $xmlarr['attributes']['status'] != 'success' )
		{
			derr('API reported a failure: '.$c->__tostring());
		}

        if( !is_null($filecontent) )
        {
            return $xmlarr['children'];
        }
        if( !$checkResultTag )
        {
            return $xmlarr['children'];
        }


        //print_r( $xmlarr['children'] );

        $cursor = &searchForName('name', 'result', $xmlarr['children']);

        if( is_null($cursor) )
        {
            derr('XML API response has no <result> field:'.$c->__tostring());
        }
		
        if( is_null( $cursor['children'] ) )
        {
            derr('XML API <result> has no content');
        }
		
		
		return $cursor['children'];
	}


   
	
	
	public function &getRunningConfig()
	{
		$url = 'action=show&type=config&xpath=/config';
		
		$r = &$this->sendRequest($url, true);

        $cursor = &searchForName('name', 'config', $r);

        if( is_null($cursor) )
        {
            derr("<config> was not found");
        }
		
		return $cursor;
	}

    public function &getCandidateConfig()
    {
        $url = 'action=get&type=config&xpath=/config';
        
        $r = &$this->sendRequest($url, true);

        $cursor = &searchForName('name', 'config', $r);

        if( is_null($cursor) )
        {
            derr("<config> was not found");
        }
        
        return $cursor;
    }


    public function &sendSetRequest($xpath, $element)
    {
        $url = "type=config&action=set&xpath=$xpath&element=$element";
        return $this->sendRequest($url);
    }

    public function &sendEditRequest($xpath, $element)
    {
        $url = "type=config&action=edit&xpath=$xpath&element=$element";
        return $this->sendRequest($url);
    }

    public function &sendDeleteRequest($xpath)
    {
        $url = "type=config&action=delete&xpath=$xpath";
        return $this->sendRequest($url);
    }

    public function &sendRenameRequest($xpath, $newname)
    {
        $url = "type=config&action=rename&xpath=$xpath&newname=$newname";
        return $this->sendRequest($url);
    }

    
}


/**
* @ignore
*/
class mycurl
{ 
     protected $_useragent = 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1'; 
     protected $_url; 
     protected $_followlocation; 
     protected $_timeout; 
     protected $_maxRedirects; 
     protected $_cookieFileLocation = './cookie.txt'; 
     protected $_post; 
     protected $_postFields; 
     protected $_referer ="http://panapiconnector"; 

     protected $_session; 
     protected $_webpage; 
     protected $_includeHeader; 
     protected $_noBody; 
     protected $_status; 
     protected $_binaryTransfer;

     protected $_infilecontent;
     protected $_infilename;

     public    $authentication = 0; 
     public    $auth_name      = ''; 
     public    $auth_pass      = ''; 

     public function useAuth($use){ 
       $this->authentication = 0; 
       if($use == true) $this->authentication = 1; 
     } 

     public function setName($name){ 
       $this->auth_name = $name; 
     } 
     public function setPass($pass){ 
       $this->auth_pass = $pass; 
     } 

     public function __construct($url,$followlocation = false,$timeOut = 30,$maxRedirecs = 4,$binaryTransfer = false,$includeHeader = false,$noBody = false) 
     { 
         $this->_url = $url; 
         $this->_followlocation = $followlocation; 
         $this->_timeout = $timeOut; 
         $this->_maxRedirects = $maxRedirecs; 
         $this->_noBody = $noBody; 
         $this->_includeHeader = $includeHeader; 
         $this->_binaryTransfer = $binaryTransfer; 
         $this->_infilecontent = null;

         $this->_cookieFileLocation = dirname(__FILE__).'/cookie.txt'; 

     } 

     public function setReferer($referer){ 
       $this->_referer = $referer; 
     } 

     public function setCookiFileLocation($path) 
     { 
         $this->_cookieFileLocation = $path; 
     } 

     public function setPost (&$postFields) 
     { 
        $this->_post = true; 
        $this->_postFields = &$postFields; 
     } 

     public function setUserAgent($userAgent) 
     { 
         $this->_useragent = $userAgent; 
     } 

     public function createCurl(&$url = 'nul') 
     { 
        if($url != 'nul'){ 
          $this->_url = $url; 
        } 

         $s = curl_init(); 

         curl_setopt($s,CURLOPT_URL, str_replace(' ', '%20',$this->_url) ); 
         //curl_setopt($s,CURLOPT_HTTPHEADER,array('Expect:')); 
         curl_setopt($s,CURLOPT_TIMEOUT,$this->_timeout); 
         curl_setopt($s,CURLOPT_MAXREDIRS,$this->_maxRedirects); 
         curl_setopt($s,CURLOPT_RETURNTRANSFER,true); 
         curl_setopt($s,CURLOPT_FOLLOWLOCATION,$this->_followlocation);
        
         //curl_setopt($s,CURLOPT_COOKIEJAR,$this->_cookieFileLocation); 
         //curl_setopt($s,CURLOPT_COOKIEFILE,$this->_cookieFileLocation); 

         if($this->authentication == 1){ 
           curl_setopt($s, CURLOPT_USERPWD, $this->auth_name.':'.$this->auth_pass); 
         } 
         if($this->_post) 
         { 
            curl_setopt($s,CURLOPT_POSTFIELDS,$this->_postFields); 
         } 

         if($this->_includeHeader) 
         { 
               curl_setopt($s,CURLOPT_HEADER,true); 
         } 

         if($this->_noBody) 
         { 
             curl_setopt($s,CURLOPT_NOBODY,true); 
         } 
         /* 
         if($this->_binary) 
         { 
             curl_setopt($s,CURLOPT_BINARYTRANSFER,true); 
         } 
         */ 
         curl_setopt($s,CURLOPT_USERAGENT,$this->_useragent); 
         curl_setopt($s,CURLOPT_REFERER,$this->_referer); 
         
         curl_setopt($s,CURLOPT_SSL_VERIFYPEER,false);
         curl_setopt($s,CURLOPT_SSL_VERIFYHOST,false);
         //curl_setopt($s,CURLOPT_VERBOSE, 1); 


         if( !is_null($this->_infilecontent) )
         {


            

            $content =  "----ABC1234\r\n"
                        . "Content-Disposition: form-data; name=\"file\"; filename=\"".$this->_infilename."\"\r\n"
                        . "Content-Type: application/xml\r\n"
                        . "\r\n"
                        . $this->_infilecontent . "\r\n"
                        . "----ABC1234--\r\n";

            //print "content length = ".strlen($content)."\n";            
            curl_setopt($s, CURLOPT_HTTPHEADER, Array('Content-Type: multipart/form-data; boundary=--ABC1234') );
            curl_setopt($s, CURLOPT_POST, true); 
            curl_setopt($s, CURLOPT_POSTFIELDS, $content);

         }

         $er = curl_exec($s);
         
         if( $er === FALSE )
         {
         	 $this->last_error = curl_error($s);
         	 return false;
         }
         
         $this->_webpage = $er; 
         
         
         $this->_status = curl_getinfo($s,CURLINFO_HTTP_CODE); 
         curl_close($s); 
         
         return true;

     } 

   public function getHttpStatus() 
   { 
       return $this->_status; 
   } 

   public function setInfile( &$fc, $filename )
   {
        $this->_infilecontent = &$fc;
        $this->_infilename = $filename;
   }

   public function __tostring(){ 
      return $this->_webpage; 
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

function searchForGroup(&$objects, $subname, $groupname)
{
	if( !isset($objects[$subname]) )
		return null;

	if( !isset($objects[$subname]['address'][$groupname]) )
		return null;

	return $objects[$subname]['address'][$groupname];
}

function &resolveGroupOrDie(&$objects, $subname, &$group)
{
	$ret = Array();

	if( !isset($objects[$subname]) )
		die("Error: cannot find vsys/device-group '$subname'\n\n");

	foreach($group['members'] as &$member )
	{
		$m = Array();
		$m['name'] = $member;
		if( isset($objects[$subname]['address'][$member]) )
		{
			$m['sub'] = $subname;
			$m['type'] = $objects[$subname]['address'][$member]['type'];
		}
		else if( isset($objects['shared']['address'][$member]) )
		{
			$m['sub'] = 'shared';
			$m['type'] = $objects['shared']['address'][$member]['type'];
		}
		else
			die("Error : cannot resolve member named '$member'\n\n");


		print "member: ".$m['sub']."/".$m['name']."\n";

		$ret[] = $m;
	}


	return $ret;
}

function tagObjects(&$list, $tagName, $modePANOS, PanAPIConnector $connector)
{

	print "creating tag '$tagName'...";
	$xpath = '/config/shared/tag';
	$element = "<entry name='".$tagName."'></entry>";
	$connector->sendSetRequest($xpath,$element);
	print " OK!\n";

	foreach( $list as &$o )
	{
		$xpath = '/'.$o['type']."/entry[@name='".$o['name']."']/tag";
		$element= "<member>$tagName</member>";
		
		if( $o['sub'] == 'shared' )
		{
			$xpath = '/config/shared'.$xpath;
		}
		else
		{
			if( $modePANOS )
				$xpath = "/config/devices/entry/vsys/entry[@name='".$o['sub']."']".$xpath;
			else
				$xpath = "/config/devices/entry/device-group/entry[@name='".$o['sub']."']".$xpath;


		}

		print "Tagging object ".$o['sub']."/".$o['name']."... ";
		//$connector->setShowApiCalls(true);
		$connector->sendSetRequest($xpath, $element);
		print "OK!\n";
	}
}




/******************
* script starts here
*
*/

$con = new PanAPIConnector($argv[1], '');
//$con->setShowApiCalls(true);

print "Requesting API key...";
$res = &$con->sendRequest("type=keygen&user=$argv[2]&password=$argv[3]");

$res = &searchForName('name', 'result', $res);
if( $res === null )
	derr('error');

$res = &searchForName('name', 'key', $res['children']);
if( $res === null )
	derr('error');

if( strlen($res['content']) < 1 )
	derr('error');

$con->apikey = $res['content'];
print "OK, key is $con->apikey\n\n";
// end of API key extraction


// PANOS or Panorama ?
print "Determining is PANOS or Panorama... ";
$res = &$con->sendRequest("type=op&cmd=<show><system><info></info></system></show>");

$res = &searchForName('name', 'result', $res);
if( $res === null )
	derr('error');
$res = &searchForName('name', 'system', $res['children']);
if( $res === null )
	derr('error');

$version = &searchForName('name', 'sw-version', $res['children']);
if( $version === null )
	derr('cannot find PANOS version');


$res = &searchForName('name', 'model', $res['children']);
if( $res === null )
	derr('cannot find host type');

if( $res['content'] == 'Panorama' )
{
	$panos = false;
	print "Panorama found!\n";
}
else
{
	$panos = true;
	print "PANOS found!\n";
}

$vex = explode('.', $version['content']);
if( count($vex) != 3 || $vex[0] < 6 )
	die("ERROR! Unsupported PANOS version :  ".$version['content']."\n\n");

print "PANOS version: ".$version['content']." OK (>=6.0)!\n";

//
print "Downloading config from device...";
$res = &$con->getRunningConfig();
print "OK!\n";


$sharedCursor = &searchForName('name', 'shared', $res['children']);
if( $sharedCursor === null )
	derr('cannot find <shared> in config');

$objects = Array();
$objects['shared'] = Array();
$objects['shared']['address'] = Array();

$tmp = &searchForName('name', 'address', $sharedCursor['children']);
if( $tmp !== NULL )
{
	foreach( $tmp['children'] as &$o )
	{
		//print "address object named '".$o['attributes']['name']."' found\n";
		$newa = Array();
		$newa['type'] = 'address';
		$objects['shared']['address'][$o['attributes']['name']] = $newa;
	}
}

$tmp = &searchForName('name', 'address-group', $sharedCursor['children']);
if( $tmp !== NULL )
{
	foreach( $tmp['children'] as &$o )
	{
		//print "address group object named '".$o['attributes']['name']."' found\n";

		$newa = Array();
		$newa['type'] = 'address-group';
		$newa['subtype'] = 'notstatic';

		$grouproot = &searchForName('name', 'static', $o['children']);
		if( $grouproot !== NULL )
		{
			$newa['members'] = Array();
			$newa['subtype'] = 'static';

			foreach ( $grouproot['children'] as &$member )
			{
				//print "found group member: ".$member['content']."\n";
				$newa['members'][] = $member['content'];
			}
		}

		$objects['shared']['address'][$o['attributes']['name']] = $newa;
	}
}

$deviceCursor = &searchForName('name', 'devices', $res['children']);
if( $deviceCursor === null )
	derr('cannot find <devices> in config');

if( !isset($deviceCursor['children'][0]) )
	derr('cannot find <entry name="localhost.localdomain"> in config');

$deviceCursor = $deviceCursor['children'][0];


if( $panos )
	$subs = &searchForName('name', 'vsys', $deviceCursor['children']);
else
	$subs = &searchForName('name', 'device-group', $deviceCursor['children']);

if( $subs !== NULL )
{
	foreach( $subs['children'] as &$sub )
	{
		print "sub system '".$sub['attributes']['name']."' found\n";
		$lname = $sub['attributes']['name'];
		$objects[$lname] = Array();
		$objects[$lname]['address'] = Array();
		$objects[$lname]['address-group'] = Array();


		$tmp = &searchForName('name', 'address', $sub['children']);
		if( $tmp !== NULL )
		{
			foreach( $tmp['children'] as &$o )
				{
					//print "address object named '".$o['attributes']['name']."' found\n";
					$newa = Array();
					$newa['type'] = 'address';
					$objects[$lname]['address'][$o['attributes']['name']] = $newa;
				}
		}

		$tmp = &searchForName('name', 'address-group', $sub['children']);
		if( $tmp !== NULL )
		{
			foreach( $tmp['children'] as &$o )
			{
				//print "address group object named '".$o['attributes']['name']."' found\n";

				$newa = Array();
				$newa['type'] = 'address-group';
				$newa['subtype'] = 'notstatic';

				$grouproot = &searchForName('name', 'static', $o['children']);
				if( $grouproot !== NULL )
				{
					$newa['members'] = Array();
					$newa['subtype'] = 'static';

					foreach ( $grouproot['children'] as &$member )
					{
						//print "found group member: ".$member['content']."\n";
						$newa['members'][] = $member['content'];
					}
				}

				$objects[$lname]['address'][$o['attributes']['name']] = $newa;
			}
		}


	}
}

//print_r($objects);

$group = searchForGroup($objects, $requestSubSystem, $requestGroup);

if( $group === null )
{
	die("Error: Group named '$requestGroup' cannot be found in '$requestSubSystem'\n\n");
}

if( $group['subtype'] != 'static' )
	die("Error: $requestSubSystem/$requestGroup is not a static group\n\n");

print "\n\nGroup $requestSubSystem/$requestGroup was found and contains ".count($group['members'])." objects, now resolving its members...\n";

$members = resolveGroupOrDie($objects, $requestSubSystem, $group);

$tagname = 'grp.'.$requestGroup;

tagObjects($members, $tagname, $panos, $con);

print "All objects are tagged, now changing static group into a dynamic one...";

$xpath = "/address-group/entry[@name='".$requestGroup."']";
$element = "<dynamic><filter>'".$tagname."'</filter></dynamic>";

if( $requestSubSystem == 'shared' )
{
	$xpath = '/config/shared'.$xpath;
}
else
{
	if( $panos )
			$xpath = "/config/devices/entry/vsys/entry[@name='".$requestSubSystem."']".$xpath;
		else
			$xpath = "/config/devices/entry/device-group/entry[@name='".$requestSubSystem."']".$xpath;
}

$con->sendSetRequest($xpath,$element);
print "OK!\n\n SUCCESS , don't forget to commit !\n\n";





