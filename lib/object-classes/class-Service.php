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


class Service
{
	use PathableName;
	use XmlConvertible;
    use ObjectWithDescription;
    use ServiceCommon;

	protected $_protocol = 'tcp';
	protected $_dport = '';
	protected $_sport = '';

	/** @var null|DOMElement */
	public $protocolRoot = null;

    /** @var null|DOMElement */
    protected $tcpOrUdpRoot = null;

	/** @var null|DOMElement */
	public $dportroot = null;
	
	public $type = '';

	/** @var ServiceStore */
	public $owner=null;

    /** @var TagRuleContainer */
    public $tags;


    /**
     * @param $name
     * @param ServiceStore $owner
     * @param bool $fromTemplateXml
     */
	function __construct($name, $owner=null, $fromTemplateXml=false)
	{
		
		if( $fromTemplateXml )
		{
            $doc = new DOMDocument();
            $doc->loadXML(self::$templatexml);

            $node = DH::findFirstElementOrDie('entry',$doc);

            $rootDoc = $owner->serviceRoot->ownerDocument;
            $this->xmlroot = $rootDoc->importNode($node, true);
            $this->owner = $owner;
            $this->load_from_domxml($this->xmlroot);
            $this->owner = null;

            $this->setName($name);
		}
		else
			$this->name = $name;
			
		$this->owner = $owner;
        $this->tags = new TagRuleContainer($this);
		
	}


    /**
     * @param DOMElement $xml
     * @throws Exception
     */
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
		$this->protocolRoot = DH::findFirstElementOrDie('protocol', $xml);
		
		$this->tcpOrUdpRoot = DH::findFirstElement('tcp', $this->protocolRoot );

		if( $this->tcpOrUdpRoot === FALSE )
		{
			$this->_protocol = 'udp';
			$this->tcpOrUdpRoot = DH::findFirstElement('udp', $this->protocolRoot );
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

        if( $this->owner->owner->version >= 60 )
        {
            $tagRoot = DH::findFirstElement('tag', $xml);
            if( $tagRoot !== false )
                $this->tags->load_from_domxml($tagRoot);
        }
	}

    /**
     * @param string $newPorts
     * @return bool
     */
	public function setDestPort($newPorts)
	{
        if( strlen($newPorts) == 0 )
            derr("invalid blank value for newPorts");

        if( $newPorts == $this->_dport )
            return false;

		$this->_dport = $newPorts;
		$tmp = DH::findFirstElementOrCreate('port', $this->tcpOrUdpRoot, $this->_dport);
        DH::setDomNodeText($tmp, $newPorts);
        return true;
	}

    /**
     * @param string $newPorts
     * @return bool
     */
    public function API_setDestPort($newPorts)
    {
        $ret = $this->setDestPort($newPorts);
        $connector = findConnectorOrDie($this);

        $this->API_sync();

        return $ret;
    }


    public function setSourcePort($newPorts)
    {
        if( $newPorts === null || strlen($newPorts) == 0 )
        {
            if( strlen($this->_sport) == 0 )
                return false;

            $this->_sport = $newPorts;
            $sportroot = DH::findFirstElement('source-port', $this->tcpOrUdpRoot);
            if( $sportroot !== false )
                $this->tcpOrUdpRoot->removeChild($sportroot);

            return true;
        }
        if( $this->_sport == $newPorts )
            return false;

        if( strlen($this->_sport) == 0 )
        {
            DH::findFirstElementOrCreate('source-port', $this->tcpOrUdpRoot,$newPorts);
            return true;
        }
        $sportroot = DH::findFirstElementOrCreate('source-port', $this->tcpOrUdpRoot);
        DH::setDomNodeText($sportroot, $newPorts);
        return true;
    }

    public function isTcp()
    {
        if( $this->_protocol == 'tcp' )
            return true;

        return false;
    }

    public function isUdp()
    {
        if( $this->_protocol == 'udp' )
            return true;

        return false;
    }

    /**
     * @param string $newProtocol
     */
	public function setProtocol($newProtocol)
	{
        if( $newProtocol != 'tcp' && $newProtocol != 'udp' )
            derr("unsupported protocol '{$newProtocol}'");

        if( $newProtocol == $this->_protocol )
            return;

		$this->_protocol = $newProtocol;

        DH::clearDomNodeChilds($this->protocolRoot);

        $this->tcpOrUdpRoot = DH::createElement($this->protocolRoot, $this->_protocol);

        DH::createElement($this->tcpOrUdpRoot, 'port' ,$this->_dport);

        if( strlen($this->_sport) > 0 )
            DH::createElement($this->tcpOrUdpRoot, 'source-port' ,$this->_dport);
	}

    /**
     * @return string
     */
    public function protocol()
    {
        if( $this->isTmpSrv() )
            return 'tmp';

        else
            return $this->_protocol;
    }

    /**
     * @return string
     */
	public function getDestPort()
	{
		return $this->_dport;
	}

    /**
     * @return string
     */
    public function getSourcePort()
    {
        return $this->_sport;
    }


    /**
     * @param string $newName
     */
	public function setName($newName)
	{
		$this->setRefName($newName);

        if( $this->xmlroot !== null )
		    $this->xmlroot->setAttribute('name', $newName);
	}

    /**
     * @param string $newName
     */
    public function API_setName($newName)
    {
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
		$str = $this->owner->getServiceStoreXPath()."/entry[@name='".$this->name."']";

		return $str;
	}

	public function isService()
	{
		return true;
	}


	public function isTmpSrv()
	{
		if( $this->type == 'tmp' )
			return true;

		return false;
	}


    /**
     * @param $otherObject Service|ServiceStore
     * @return bool
     */
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

		if( $otherObject->_protocol !== $this->_protocol )
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
            return new ServiceDstPortMapping();

        if( $this->_protocol == 'tcp' )
            $tcp = true;
        else
            $tcp = false;

        return ServiceDstPortMapping::mappingFromText($this->_dport, $tcp);
    }

    /**
     * @return ServiceSrcPortMapping
     * @throws Exception
     */
    public function srcPortMapping()
    {
        if( $this->isTmpSrv() )
            return new ServiceSrcPortMapping();

        if( $this->_protocol == 'tcp' )
            $tcp = true;
        else
            $tcp = false;

        return ServiceSrcPortMapping::mappingFromText($this->_sport, $tcp);
    }

	public function API_delete()
	{
		if($this->isTmpSrv())
			derr('cannot be called on a Tmp service object');

		return $this->owner->API_remove($this);
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
