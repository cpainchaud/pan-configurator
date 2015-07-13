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


class Address
{
	use ReferencableObject {removeReference as super_removeReference;}
	use PathableName;
	use XmlConvertible;
    use ObjectWithDescription;

    /**
     * @var string|null
     */
	protected $value;

    /** @var AddressStore|null */
	public $owner;

	/**
	 * @var TagStore
	 */
	public $tags;

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
     * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
     */

	
	/**
	* you should not need this one for normal use
     * @param string $name
     * @param AddressStore $owner
     * @param bool $fromXmlTemplate
	*/
	function Address( $name, $owner, $fromXmlTemplate = false)
	{
        $this->owner = $owner;

        if( $fromXmlTemplate )
        {
			$doc = new DOMDocument();
			$doc->loadXML(self::$templatexml);

			$node = DH::findFirstElementOrDie('entry', $doc);

			$rootDoc = $this->owner->addrroot->ownerDocument;
			$this->xmlroot = $rootDoc->importNode($node, true);
			$this->load_from_domxml($this->xmlroot);

            $this->name = $name;
            $this->xmlroot->setAttribute('name', $name);
        }

        $this->name = $name;

		$this->tags = new TagRuleContainer('tag', $this);
		
	}

	public function API_delete()
	{
		if($this->isTmpAddr())
			derr('cannot be called on a Tmp address object');


        return $this->owner->API_remove($this);
	}


	/**
	* @ignore
	*
	*/
	public function load_from_domxml(DOMElement $xml)
	{
		
		$this->xmlroot = $xml;
		
		$this->name = DH::findAttribute('name', $xml);
		if( $this->name === FALSE )
			derr("address name not found\n");

        $this->_load_description_from_domxml();
		
		//print "object named '".$this->name."' found\n";


		$typeFound = false;

		foreach($xml->childNodes as $node)
		{
			if( $node->nodeType != 1  )
				continue;

			$lsearch = array_search($node->nodeName, self::$AddressTypes);
			if( $lsearch !== FALSE )
			{
				$typeFound = true;
				$this->type = $lsearch;
				$this->value = $node->textContent;
			}
		}

		if( !$typeFound )
			derr('object type not found or not supported');

		if( $this->owner->owner->version >= 60 )
		{
			$tagRoot = DH::findFirstElement('tag', $xml);
			if( $tagRoot !== false )
				$this->tags->load_from_domxml($tagRoot);
		}

	}

    /**
     * @return null|string
     */
	public function value()
	{
		return $this->value;
	}

	/**
	 * @param string|null $newDesc
	 * @return bool
	 */
	public function API_setDescription($newDesc)
	{
		$ret = $this->setDescription($newDesc);

		if( $ret )
		{
			$con = findConnectorOrDie($this);
			if( $this->_description === null )
				$con->sendDeleteRequest($this->getXPath().'/description');
			else
				$con->sendSetRequest($this->getXPath(), '<description>'.$this->_description.'</description>');
		}

		return $ret;
	}

    /**
     * @param string $newValue
     * @param bool $rewriteXml
     * @return bool
     * @throws Exception
     */
	public function setValue( $newValue, $rewriteXml = true )
	{
        if( isset($this->_ip4Map) )
            unset($this->_ip4Map);

		if( !is_string($newValue) )
			derr('value can be text only');

		if( $newValue == $this->value )
			return false;

		if( $this->isTmpAddr() )
			return false;

		$this->value = $newValue;

		if( $rewriteXml)
		{

			$valueRoot = DH::findFirstElementOrDie(self::$AddressTypes[$this->type], $this->xmlroot);
			$valueRoot->nodeValue = $this->value;

		}

		return true;
	}

    /**
     * @param $newType string
     * @param bool $rewritexml
     * @return bool true if successful
     */
	public function setType( $newType, $rewritexml = true )
	{
        if( isset($this->_ip4Map) )
            unset($this->_ip4Map);

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
		if( !$this->setType($newType) )
			return false;

		$c = findConnectorOrDie($this);
		$xpath = $this->getXPath();

		$c->sendSetRequest($xpath,  DH::dom_to_xml($this->xmlroot,-1,false) );

		$this->setType($newType);

        return true;
	}

    /**
     * @param string $newValue
     * @return bool
     */
	public function API_setValue($newValue)
	{
		if( !$this->setValue($newValue) )
			return false;

		$c = findConnectorOrDie($this);
		$xpath = $this->getXPath();

		$c->sendSetRequest($xpath,  DH::dom_to_xml($this->xmlroot,-1,false) );

		$this->setValue($newValue);

        return true;
	}
	
	
	
	public function rewriteXML()
	{
        if( $this->isTmpAddr() )
            return;

		DH::clearDomNodeChilds($this->xmlroot);

		$tmp = DH::createElement($this->xmlroot, self::$AddressTypes[$this->type], $this->value);

		if( $this->_description !== null && strlen($this->_description) > 0 )
		{
			DH::createElement($this->xmlroot, 'description', $this->_description );
		}

	}
	
	/**
	 * change the name of this object
	 * @param string $newName
     *
	*/
	public function setName($newName)
	{
		$this->setRefName($newName);
		$this->xmlroot->setAttribute('name', $newName);
	}

    /**
     * @param string $newName
     */
	public function API_setName($newName)
	{
		$c = findConnectorOrDie($this);
		$path = $this->getXPath();

		$url = "type=config&action=rename&xpath=$path&newname=$newName";

		$c->sendRequest($url);

		$this->setName($newName);
	}


    /**
     * @return string
     */
	public function &getXPath()
	{
		$str = $this->owner->getAddressStoreXPath()."/entry[@name='".$this->name."']";

		return $str;
	}


	/**
	* @return string ie: 'ip-netmask' 'ip-range'
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

    /**
     * @param $otherObject Address|AddressGroup
     * @return bool
     */
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
     * @return IP4Map
     */
    public function getIP4Mapping()
    {
        if( isset($this->_ip4Map) )
        {
            return $this->_ip4Map;
        }

        if( $this->isTmpAddr() )
        {
            if( filter_var($this->name, FILTER_VALIDATE_IP) === false  )
            {
                derr('cannot resolve a Temporary object !');
            }
            $this->_ip4Map = IP4Map::mapFromText($this->name);
        }
        elseif( $this->type != self::TypeIpRange && $this->type != self::TypeIpNetmask )
            derr('cannot resolve an object of type '.$this->type());
        elseif( $this->type == self::TypeIpNetmask || $this->type == self::TypeIpRange )
        {
            $this->_ip4Map = IP4Map::mapFromText($this->value);
        }
        else
        {
            derr("unexpected type");
        }

        return $this->_ip4Map;
    }



    /**
     * return 0 if not match, 1 if this object is fully included in $network, 2 if this object is partially matched by $ref.
     * @param $network string|IP4Map ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function  includedInIP4Network($network)
    {
        if( $this->type != self::TypeIpNetmask && $this->type != self::TypeIpRange )
            return 0;

        if( is_object($network) )
        {
            $networkMap = $network;
        }
        else
            $networkMap = IP4Map::mapFromText($network);


        return cidr::netMatch($this->getIP4Mapping()->getFirstMapEntry(), $networkMap->getFirstMapEntry());
    }

    /**
     * return 0 if not match, 1 if $network is fully included in this object, 2 if $network is partially matched by this object.
     * @param $network|IP4Map ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function  includesIP4Network($network)
    {
        if( $this->type != self::TypeIpNetmask && $this->type != self::TypeIpRange )
            return 0;

        if( is_object($network) )
        {
            $networkMap = $network;
        }
        else
            $networkMap = IP4Map::mapFromText($network);


        return cidr::netMatch($networkMap->getFirstMapEntry(), $this->getIP4Mapping()->getFirstMapEntry());
    }


	public function removeReference($object)
	{
		$this->super_removeReference($object);

        // adding extra cleaning
		if( $this->isTmpAddr() && $this->countReferences() == 0 && $this->owner !== null )
		{
			$this->owner->remove($this);
		}

	}

    static protected $templatexml = '<entry name="**temporarynamechangeme**"><ip-netmask>tempvaluechangeme</ip-netmask></entry>';
	
}


