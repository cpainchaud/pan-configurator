<?php

/*
 * Copyright (c) 2014-2017 Christophe Painchaud <shellescape _AT_ gmail.com>
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

/**
 * @property $_ip4Map IP4Map cached ip start and end value for fast optimization
 */
class Address
{
	use AddressCommon;
	use PathableName;
	use XmlConvertible;
    use ObjectWithDescription;

    /** @var string|null */
	protected $value;

    /** @var AddressStore|null */
	public $owner;

	/** @var TagRuleContainer */
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
	* you should not need this one for normal use
     * @param string $name
     * @param AddressStore $owner
     * @param bool $fromXmlTemplate
	*/
	function __construct( $name, $owner, $fromXmlTemplate = false)
	{
        $this->owner = $owner;

        if( $fromXmlTemplate )
        {
			$doc = new DOMDocument();
			$doc->loadXML(self::$templatexml);

			$node = DH::findFirstElementOrDie('entry', $doc);

			$rootDoc = $this->owner->addressRoot->ownerDocument;
			$this->xmlroot = $rootDoc->importNode($node, true);
			$this->load_from_domxml($this->xmlroot);

            $this->name = $name;
            $this->xmlroot->setAttribute('name', $name);
        }

        $this->name = $name;

		$this->tags = new TagRuleContainer($this);
		
	}


	/**
	* @ignore
	* @param DOMElement $xml
     * @return bool TRUE if loaded ok, FALSE if not
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
            /** @var DOMElement $node */

			if( $node->nodeType != XML_ELEMENT_NODE  )
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
        {
            if( !PH::$ignoreInvalidAddressObjects )
                derr('Object type not found or not supported for address object ' . $this->name . '. Please check your configuration file and fix it or invoke ith argument "shadow-ignoreInvalidAddressObjects"', $xml);

            mwarning('Object type not found or not supported for address object ' . $this->name . ' but you manually did bypass this error', $xml);
            return false;
        }

		if( $this->owner->owner->version >= 60 )
		{
			$tagRoot = DH::findFirstElement('tag', $xml);
			if( $tagRoot !== false )
				$this->tags->load_from_domxml($tagRoot);
		}


		return true;
	}

    /**
     * @return null|string
     */
	public function value()
	{
		if( $this->isTmpAddr() )
		{
			if( $this->nameIsValidRuleIPEntry() )
				return $this->name();
		}

		return $this->value;
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
			DH::setDomNodeText($valueRoot, $this->value);
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

        if( $this->tags->count() > 0 )
        {
            $this->tags->xmlroot = DH::createElement($this->xmlroot, 'tag');
            $this->tags->rewriteXML();
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

		if( $this->isTmpAddr() )
			unset($this->_ip4Map);
	}

    /**
     * @param string $newName
     */
	public function API_setName($newName)
	{
        if( $this->isTmpAddr() )
        {
            mwarning('renaming of TMP object in API is not possible, it was ignored');
            return;
        }
		$c = findConnectorOrDie($this);
		$xpath = $this->getXPath();
        $c->sendRenameRequest($xpath, $newName);
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

    public function isType_ipNetmask()
    {
        return $this->type == self::TypeIpNetmask;
    }

    public function  isType_ipRange()
    {
        return $this->type == self::TypeIpRange;
    }

    public function isType_FQDN()
    {
        return $this->type == self::TypeFQDN;
    }

    public function isType_TMP()
    {
        return $this->type == self::TypeTmp;
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
            if( ! $this->nameIsValidRuleIPEntry()  )
            {
                // if this object is temporary/unsupported, we send an empty mapping
                $this->_ip4Map = new IP4Map();
                $this->_ip4Map->unresolved[$this->name] = $this;
            }
            else
                $this->_ip4Map = IP4Map::mapFromText($this->name);
        }
        elseif( $this->type != self::TypeIpRange && $this->type != self::TypeIpNetmask )
        {
            $this->_ip4Map = new IP4Map();
            $this->_ip4Map->unresolved[$this->name] = $this;
        }
        elseif( $this->type == self::TypeIpNetmask || $this->type == self::TypeIpRange )
        {
            $this->_ip4Map = IP4Map::mapFromText($this->value);
            if( $this->_ip4Map->count() == 0 )
                $this->_ip4Map->unresolved[$this->name] = $this;
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
        if( $this->type != self::TypeIpNetmask && $this->type != self::TypeIpRange && !$this->isTmpAddr() )
            return 0;

        if( is_object($network) )
        {
            $networkMap = $network;
        }
        else
            $networkMap = IP4Map::mapFromText($network);

        $localEntry = $networkMap->getFirstMapEntry();
        if( $localEntry === null )
            return 0;

        $networkEntry = $this->getIP4Mapping()->getFirstMapEntry();
        if( $networkEntry === null )
            return 0;

        return cidr::netMatch($localEntry, $networkEntry);
    }

    /**
     * return 0 if not match, 1 if $network is fully included in this object, 2 if $network is partially matched by this object.
     * @param $network string|IP4Map ie: 192.168.0.2/24, 192.168.0.2,192.168.0.2-192.168.0.4
     * @return int
     */
    public function  includesIP4Network($network)
    {
        if( $this->type != self::TypeIpNetmask && $this->type != self::TypeIpRange && !$this->isTmpAddr() )
            return 0;

        if( is_object($network) )
        {
            $networkMap = $network;
        }
        else
            $networkMap = IP4Map::mapFromText($network);

        $localEntry = $networkMap->getFirstMapEntry();
        if( $localEntry === null )
            return 0;

        $networkEntry = $this->getIP4Mapping()->getFirstMapEntry();
        if( $networkEntry === null )
            return 0;


        return cidr::netMatch($networkEntry, $localEntry);
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

	public function getNetworkMask()
    {
        if( $this->type !== self::TypeIpNetmask )
            return FALSE;

        $explode = explode('/', $this->value );

        if( count($explode) < 2 )
            return 32;

        else
            return intval($explode[1]);
    }

    /**
     * @return bool|string
     */
    public function getNetworkValue()
    {
        if( $this->type !== self::TypeIpNetmask )
            return FALSE;

        $explode = explode('/', $this->value );

        if( count($explode) < 2 )
            return $this->value;

        else
            return $explode[0];
    }

	public function nameIsValidRuleIPEntry()
	{
		if( filter_var($this->name, FILTER_VALIDATE_IP) !== false  )
			return true;

        $ex = explode( '-', $this->name );

        if( count($ex) == 2 )
        {
            if( filter_var($ex[0], FILTER_VALIDATE_IP) === FALSE || filter_var($ex[1], FILTER_VALIDATE_IP) === FALSE )
            {
                return false;
            }
            return true;
        }

		$ex = explode('/', $this->name);

		if( count($ex) != 2 )
			return false;

		$mask = &$ex[1];
		if( !is_numeric($mask) )
			return false;

		if( (int) $mask > 32 || (int) $mask < 0 )
			return false;

		if( filter_var($ex[0], FILTER_VALIDATE_IP) !== false  )
			return true;

		return false;

	}

    static protected $templatexml = '<entry name="**temporarynamechangeme**"><ip-netmask>tempvaluechangeme</ip-netmask></entry>';
	
}


