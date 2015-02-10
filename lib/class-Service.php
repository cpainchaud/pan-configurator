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

class Service
{

	use ReferencableObject {unrefInRule as super_unrefInRule;}
	use PathableName;
	use XmlConvertible;
	
	public $description = '';
	public $protocol = 'tcp';
	public $dport = '';
	public $sport = '';

	/**
	 * @var null|DOMElement
	 */
	public $xmlroot = null;
	/**
	 * @var null|DOMElement
	 */
	public $protocolroot = null;
	/**
	 * @var null|DOMElement
	 */
	public $dportroot = null;
	/**
	 * @var null|DOMElement
	 */
	public $descroot = null;
	
	public $type = '';

	/**
	 * @var ServiceStore
	 */
	public $owner=null;
	
	
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
	
	public function load_from_xml(&$xml)
	{
		$this->xmlroot = &$xml;
		$this->name = $xml['attributes']['name'];
		if( is_null($this->name) )
		{
			print_r($xml);
			derr("service name not found\n");
		}
		
		// seeking <description>
		$this->descroot = &searchForName('name', 'description', $xml['children']);
		if( $this->descroot )
		{
			$this->description = $this->descroot['content'];
		}
		else
		{
			$this->descroot = Array('name'=>'ignme','content'=>$this->description);
			$this->xmlroot['children'][] = &$this->descroot;
		}
		
		//
		// seeking <protocol>
		//
		$this->protocolroot = &searchForName('name', 'protocol', $xml['children']);
		if( ! $this->protocolroot )
			derr("Error: <protocol> not found for service".$this->name."\n");
		
		$portroot = &searchForName('name', 'tcp', $this->protocolroot['children']);

		if( ! $portroot )
		{
			$this->protocol = 'udp';
			$portroot = &searchForName('name', 'udp', $this->protocolroot['children']);
		}
		if( ! $portroot )
			derr("Error: <tcp> or <udp> not found for service".$this->name."\n");
		
		$this->dportroot = &searchForName('name', 'port', $portroot['children']);
		if( ! $this->dportroot )
			derr("Error: <port> not found for service".$this->name."\n");
		
		$this->dport = $this->dportroot['content'];
		
		$sportroot = &searchForName('name', 'sport', $portroot['children']);
		if( $sportroot )
		{
			$this->sport = $sportroot['content'];
		}
	}



	public function load_from_domxml($xml)
	{
		$this->xmlroot = $xml;
		
		$this->name = DH::findAttribute('name', $xml);
		if( $this->name === FALSE )
			derr("service name not found\n");
		
		$this->descroot = DH::findFirstElement('description', $xml);
        if( $this->descroot === false )
        {
            $this->descroot = null;
        }
        else
		    $this->description = $this->descroot->textContent;
		
		//
		// seeking <protocol>
		//
		$this->protocolroot = DH::findFirstElementOrDie('protocol', $xml);
		
		$portroot = DH::findFirstElement('tcp', $this->protocolroot );

		if( $portroot === FALSE )
		{
			$this->protocol = 'udp';
			$portroot = DH::findFirstElement('udp', $this->protocolroot );
		}
		if( $portroot === FALSE )
			derr("Error: <tcp> or <udp> not found for service".$this->name."\n");
		
		$this->dportroot = DH::findFirstElementOrDie('port', $portroot );
		
		$this->dport = $this->dportroot->textContent;
		
		$sportroot = DH::findFirstElement('sport', $this->protocolroot);
		if( $sportroot !== FALSE )
		{
			$this->sport = $sportroot->textContent;
		}
	}
	
	public function setDestPort($newport)
	{
		$this->dport = $newport;
		$this->dportroot['content'] = $this->dport;
	}

	public function setProtocol($newport)
	{
		$this->protocol = $newport;
		$this->portroot['name'] = $this->protocol;
	}
	
	public function getDestPort()
	{
		return $this->dport;
	}
	

	
	public function setName($newname)
	{
		$this->setRefName($newname);

		if( PH::$UseDomXML === TRUE )
			$this->xmlroot->getAttributeNode('name')->value = $newname;
		else
			$this->xmlroot['attributes']['name'] = $newname;	
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

		if( $otherObject->isTmpSrv() && !$this->isTmpSev() )
			return false;

		if( $otherObject->protocol != $this->protocol )
			return false;

		if( $otherObject->dport != $this->dport )
			return false;

		if( $otherObject->sport != $this->sport )
			return false;

		return true;
	}


	public function API_delete()
	{
		if($this->isTmpSrv())
			derr('cannot be called on a Tmp service object');

		$connector = findConnectorOrDie($this);
		$xpath = $this->getXPath();

		$connector->sendDeleteRequest($xpath);
	}

	public function unrefInRule($object)
	{
		$this->super_unrefInRule($object);

		if( $this->isTmpSrv() && $this->countReferences() == 0 && $this->owner !== null )
		{
			$this->owner->remove($this);
		}

	}
	
	static protected $templatexml = '<entry name="**temporarynamechangeme**"><protocol><tcp><port>0</port></tcp></protocol></entry>'; 
	static protected $templatexmlroot = null;
	
}
