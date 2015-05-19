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

class Service
{

	use ReferencableObject {removeReference as super_removeReference;}
	use PathableName;
	use XmlConvertible;
    use ObjectWithDescription;

	public $protocol = 'tcp';
	protected $_dport = '';
	protected $_sport = '';

	/** @var null|DOMElement */
	public $protocolroot = null;

    /** @var null|DOMElement */
    protected $tcpOrUdpRoot = null;

	/**
	 * @var null|DOMElement
	 */
	public $dportroot = null;
	
	public $type = '';

	/**
	 * @var ServiceStore
	 */
	public $owner=null;

    /**
     * @property Array $dportMap
     * @property Array $sportMap
     */


    /**
     * @param $name
     * @param ServiceStore $owner
     * @param bool $fromtemplatexml
     */
	function Service($name, $owner=null, $fromtemplatexml=false)
	{
		
		if( $fromtemplatexml )
		{
			if( is_null(self::$templatexmlroot) )
			{
				$xmlobj = new XmlArray();
				self::$templatexmlroot = $xmlobj->load_string(self::$templatexml);
				//print_r(self::$templatexmlroot);
				//die();
			}
			
			$this->load_from_xml(cloneArray(self::$templatexmlroot));
			$this->setName($name);
		}
		else
			$this->name = $name;
			
		$this->owner = $owner;
		
	}



	public function load_from_domxml($xml)
	{
		$this->xmlroot = $xml;
		
		$this->name = DH::findAttribute('name', $xml);
		if( $this->name === FALSE )
			derr("service name not found\n");
		
        $this->_load_description_from_domxml();
		
		//
		// seeking <protocol>
		//
		$this->protocolroot = DH::findFirstElementOrDie('protocol', $xml);
		
		$this->tcpOrUdpRoot = DH::findFirstElement('tcp', $this->protocolroot );

		if( $this->tcpOrUdpRoot === FALSE )
		{
			$this->protocol = 'udp';
			$this->tcpOrUdpRoot = DH::findFirstElement('udp', $this->protocolroot );
		}
		if( $this->tcpOrUdpRoot === FALSE )
			derr("Error: <tcp> or <udp> not found for service".$this->name."\n");
		
		$this->dportroot = DH::findFirstElementOrDie('port', $this->tcpOrUdpRoot );
		
		$this->_dport = $this->dportroot->textContent;
		
		$sportroot = DH::findFirstElement('source-port', $this->tcpOrUdpRoot);
		if( $sportroot !== FALSE )
		{
			$this->_sport = $sportroot->textContent;
		}
	}
	
	public function setDestPort($newport)
	{
		$this->_dport = $newport;
		$this->dportroot['content'] = $this->_dport;
	}


    public function setSourcePort($newValue)
    {
        if( $newValue === null || strlen($newValue) == 0 )
        {
            if( strlen($this->_sport) == 0 )
                return false;

            $this->_sport = $newValue;
            $sportroot = DH::findFirstElement('source-port', $this->tcpOrUdpRoot);
            if( $sportroot !== false )
                $this->tcpOrUdpRoot->removeChild($sportroot);

            return true;
        }
        if( $this->_sport == $newValue )
            return false;

        if( strlen($this->_sport) == 0 )
        {
            DH::findFirstElementOrCreate('sport', $this->tcpOrUdpRoot,$newValue);
            return true;
        }
        $sportroot = DH::findFirstElementOrCreate('source-port', $this->tcpOrUdpRoot);
        DH::setDomNodeText($sportroot, $newValue);
        return true;
    }

	public function setProtocol($newport)
	{
		$this->protocol = $newport;
		$this->portroot['name'] = $this->protocol;
	}
	
	public function getDestPort()
	{
		return $this->_dport;
	}

    public function getSourcePort()
    {
        return $this->_sport;
    }
	

	
	public function setName($newName)
	{
		$this->setRefName($newName);

		$this->xmlroot->setAttribute('name', $newName);
	}

	public function &getXPath()
	{
		$str = $this->owner->getServiceStoreXPath()."/entry[@name='".$this->name."']";

		return $str;
	}

	public function isService()
	{
		return true;
	}

	public function isGroup()
	{
		return false;
	}

	public function isTmpSrv()
	{
		if( $this->type == 'tmp' )
			return true;

		return false;
	}


	public function equals( $otherObject )
	{
		if( ! $otherObject->isService() )
			return false;

		if( $otherObject->name != $this->name )
			return false;

		return $this->sameValue( $otherObject);
	}

	public function sameValue( Service $otherObject)
	{
		if( $this->isTmpSrv() && !$otherObject->isTmpSrv() )
			return false;

		if( $otherObject->isTmpSrv() && !$this->isTmpSrv() )
			return false;

		if( $otherObject->protocol !== $this->protocol )
			return false;

		if( $otherObject->_dport !== $this->_dport )
			return false;

		if( $otherObject->_sport !== $this->_sport )
			return false;

		return true;
	}

    /**
     * @return ServiceDstPortMapping
     * @throws Exception
     */
    public function dstPortMapping()
    {
        if( $this->isTmpSrv() )
            derr("unsupported with tmp services");

        if( $this->protocol == 'tcp' )
            $tcp = true;
        else
            $tcp = false;

        return ServiceDstPortMapping::mappingFromText($this->_dport, $tcp);
    }


	public function API_delete()
	{
		if($this->isTmpSrv())
			derr('cannot be called on a Tmp service object');

		$connector = findConnectorOrDie($this);
		$xpath = $this->getXPath();

		$connector->sendDeleteRequest($xpath);
	}

	public function removeReference($object)
	{
		$this->super_removeReference($object);

		if( $this->isTmpSrv() && $this->countReferences() == 0 && $this->owner !== null )
		{
			$this->owner->remove($this);
		}

	}
	
	static protected $templatexml = '<entry name="**temporarynamechangeme**"><protocol><tcp><port>0</port></tcp></protocol></entry>'; 
	static protected $templatexmlroot = null;
	
}
