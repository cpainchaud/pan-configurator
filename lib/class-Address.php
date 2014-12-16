<?php

/*
 * Copyright (c) 2014 Palo Alto Networks, Inc. <info@paloaltonetworks.com>
 * Author: Christophe Painchaud cpainchaud _AT_ paloaltonetworks.com
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


class Address
{
	use ReferencableObject;
	use PathableName;

    /**
     * @var string|null
     */
	protected $value;

    /**
     * @var null|string
     */
    protected $description;


    /**
     * @var null|string[]|DOMNode
     */
	public $xmlroot = null;

    /**
     * @var AddressStore|null
     */
	public $owner;

	const TypeTmp = 0;
	const TypeIpNetmask = 1;
	const TypeIpRange = 2;
	const TypeFQDN = 3;
	const TypeDynamic = 4;

	static private $AddressTypes = Array(self::TypeTmp => 'tmp',
										self::TypeIpNetmask => 'ip-netmask',
										self::TypeIpRange => 'ip-range',
										self::TypeFQDN => 'fqdn',
										self::TypeDynamic => 'dynamic'  );

	protected $type = self::TypeTmp;

	
	/**
	* you should not need this one for normal use
     * @param string name
     * @param PANConf|PanoramaConf|VirtualSystem|DeviceGroup $owner
     * @param bool $fromXmlTemplate
	*/
	function Address( $name, $owner, $fromXmlTemplate = false)
	{
        $this->owner = $owner;

        if( $fromXmlTemplate )
        {
            if( !PH::$UseDomXML )
            {
                $xmlobj = new XmlArray();
                $xmlArray = $xmlobj->load_string(self::$templatexml);
                $this->load_from_xml($xmlArray);
            }
            else
            {
                $doc = new DOMDocument();
                $doc->loadXML(self::$templatexml);

                $node = DH::findFirstElementOrDie('entry',$doc);

                $rootDoc = $this->owner->addrroot->ownerDocument;
                $this->xmlroot = $rootDoc->importNode($node, true);
                $this->load_from_domxml($this->xmlroot);

            }
            $this->setName($name);
        }

        $this->name = $name;
		
	}
	
	/**
	* @ignore
	*
	*/
	public function load_from_xml(&$xml)
	{
		
		$this->xmlroot = &$xml;
		
		$this->name = $xml['attributes']['name'];
		if( is_null($this->name) || strlen($this->name) < 1 )
			derr("address object name not found\n");
		
		//print "object named '".$this->name."' found\n";
		$typeFound = false;
		
		foreach($xml['children'] as &$cur)
		{
			$lsearch = array_search($cur['name'], self::$AddressTypes);
			if( $lsearch !== FALSE )
			{
				$typeFound = true;
				$this->type = $lsearch;
				$this->value = $cur['content'];
			}

		}

		if( !$typeFound )
			derr('object type not found or not supported');
		
		
		//print $this->type."\n";
	}

	/**
	* @ignore
	*
	*/
	public function load_from_domxml($xml)
	{
		
		$this->xmlroot = $xml;
		
		$this->name = DH::findAttribute('name', $xml);
		if( $this->name === FALSE )
			derr("address name not found\n");
		
		//print "object named '".$this->name."' found\n";

		$cur = DH::firstChildElement($xml);

		if( $cur === FALSE )
			derr("Cannot find object type for '".$this->name."'\n");

		$this->type = array_search($cur->nodeName, self::$AddressTypes);
		if( $this->type === FALSE )
			derr('invalid type found : '.$cur['name']);

		$this->value = $cur->textContent;
	}

    /**
     * @return null|string
     */
	public function value()
	{
		return $this->value;
	}

	public function description()
	{
		return $this->description;
	}

	public function setValue( $newValue, $rewritexml = true )
	{
		if( $newValue === $this->value )
			return false;

		$this->value = $newValue;

		if( $rewritexml)
			$this->rewriteXML();

		return true;
	}

    /**
     * @param $newType string
     * @param bool $rewritexml
     * @return bool true if successful
     */
	public function setType( $newType, $rewritexml = true )
	{

		$tmp = array_search( $newType, self::$AddressTypes );
		if( $tmp=== FALSE )
			derr('this type is not supported : '.$newType);

		if( $newType === $tmp )
			return false;

		$this->type = $tmp;

		if( $rewritexml)
			$this->rewriteXML();

		return true;
	}

    /**
     * @param $newType string
     * @return bool true if successful
     */
	public function API_setType($newType)
	{
		if( !$this->owner->setType($newType) )
			return false;

		$c = findConnectorOrDie($this);
		$xpath = $this->getXPath();

        // TODO fix for domXML
		$c->sendSetRequest($xpath,  array_to_xml($this->xmlroot,-1,false) );

		$this->setType($newType);

        return true;
	}

    /**
     * @param string $newValue
     * @return bool
     */
	public function API_setValue($newValue)
	{
		if( !$this->owner->setValue($newValue) )
			return false;

		$c = findConnectorOrDie($this);
		$xpath = $this->getXPath();

        // TODO fix for domXML
		$c->sendSetRequest($xpath,  array_to_xml($this->xmlroot,-1,false) );

		$this->setValue($newValue);

        return true;
	}
	
	
	
	public function rewriteXML()
	{
        if( $this->isTmpAddr() )
            return;

        // TODO need DOMXML version

		$a = Array();
		$a['name'] =  self::$AddressTypes[$this->type];
		$a['content'] = $this->value;

		$b = Array();
		$b['name'] = 'description';
		$b['content'] = $this->description;
		
		$c = Array();
		$c['name'] = 'entry';
		$c['attributes'] = Array( 'name' => $this->name);
		$c['children'] = Array( 0 => &$a, 1 => &$b );

		$this->xmlroot = $c;
	}
	
	/**
	* change the name of this object
	* @param string $newname
     *
	*/
	public function setName($newname)
	{
		$this->setRefName($newname);

		if( PH::$UseDomXML === TRUE )
			$this->xmlroot->getAttributeNode('name')->nodeValue = $newname;
		else	
			$this->xmlroot['attributes']['name'] = $newname;	
	}

	public function API_setName($newname)
	{
		$c = findConnectorOrDie($this);
		$path = $this->getXPath();

		$url = "type=config&action=rename&xpath=$path&newname=$newname";

		$c->sendRequest($url);

		$this->setName($newname);	
	}


	public function &getXPath()
	{
		$str = $this->owner->getAddressStoreXPath()."/entry[@name='".$this->name."']";

		return $str;
	}


	/**
	* @return string ie: ip-netmask
	*/
	public function type()
	{
		return self::$AddressTypes[$this->type];
	}

	public function isGroup()
	{
		return false;
	}

	public function isAddress()
	{
		return true;
	}

	public function isTmpAddr()
	{
		if( $this->type == self::TypeTmp )
			return true;

		return false;
	}

	public function equals( $otherObject )
	{
		if( ! $otherObject->isAddress() )
			return false;

		if( $otherObject->name != $this->name )
			return false;

		return $this->sameValue( $otherObject);
	}

	public function sameValue( Address $otherObject)
	{
		if( $this->isTmpAddr() && !$otherObject->isTmpAddr() )
			return false;

		if( $otherObject->isTmpAddr() && !$this->isTmpAddr() )
			return false;

		if( $otherObject->type !== $this->type )
			return false;

		if( $otherObject->value !== $this->value )
			return false;

		return true;
	}

	/**
	* Return an array['start']= startip and ['end']= endip
	* @return array 
	*/
	public function & resolveIP_Start_End()
	{
		$res = Array();

		if( $this->isTmpAddr() )
			derr('cannot resolve a Temporary object !');

		if( $this->type != self::TypeIpRange && $this->type != self::TypeIpNetmask )
			derr('cannot resolve an object of type '.$this->type());

		if( $this->type == self::TypeIpRange )
		{
			$ex = explode('-', $this->value);

			if( count($ex) != 2 )
				derr('IP range has wrong syntax: '.$this->value);

			$res['start'] = ip2log($ex[0]);
			$res['end'] = ip2log($ex[1]);
		}
		elseif( $this->type == self::TypeIpNetmask )
		{
			if( strlen($this->value) < 1 )
				derr("cannot resolve object with no value");

			$ex = explode('/', $this->value);
			if( count($ex) > 1 && $ex[1] != '32')
	    	{
	    		//$netmask = cidr::cidr2netmask($ex[0]);
	    		$bmask = 0;
	    		for($i=1; $i<= (32-$ex[1]); $i++)
	    			$bmask += pow(2, $i-1);

	    		$subNetwork = ip2long($ex[0]) & ((-1 << (32 - (int)$ex[1])) );
	    		$subBroadcast = ip2long($ex[0]) | $bmask;
	    	}
	    	elseif( $ex[1] == '32' )
	    	{
				$subNetwork = ip2long($ex[0]);
	    		$subBroadcast = $subNetwork;
	    	}
	    	else
	    	{
	    		$subNetwork = ip2long($this->value);
	    		$subBroadcast = $subNetwork;
	    	}
	    	$res['start'] = $subNetwork;
	    	$res['end'] = $subBroadcast;
		}
		else
		{
			derr("unexpected type");
		}

		return $res;
	}

    static protected $templatexml = '<entry name="**temporarynamechangeme**"><ip-netmask>tempvaluechangeme</ip-netmask></entry>';
    static protected $templatexmlroot = null;
	
}


