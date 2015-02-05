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


class DeviceGroup 
{
	
	use PathableName;
	use PanSubHelperTrait;

	/**
	 * String
	 */
	protected $name;

    /**
     * @var PanoramaConf
     */
	public $owner = null;

	/**
	 * @var DOMElement
	 */
	public $xmlroot;
	
	//public $addressroot;
	//public $addressGsroot;
	//public $servicesroot = null;
	//public $serviceGsroot = null;

	
	//public $prenatrulesroot=null;
	//public $presecrulesroot=null;
	//public $postnatrulesroot=null;
	//public $postsecrulesroot=null;

    /**
     * @var AddressStore
     */
    public $addressStore=null;
    /**
     * @var ServiceStore
     */
    public $serviceStore=null;

	public static $templatexml = '<entry name="**Need a Name**"><address></address><post-rulebase><security><rules></rules></security><nat><rules></rules></nat></post-rulebase>
									<pre-rulebase><security><rules></rules></security><nat><rules></rules></nat></pre-rulebase>
									</entry>';

	
	/**
	* @var TagStore
	*/
	public $tagStore=null;
	/**
	* @var ZoneStore
	*/
	public $zoneStore=null;
	/**
	* @var RuleStore
	*/
	public $preSecurityRules=null;
	/**
	* @var RuleStore
	*/
	public $postSecurityRules=null;
	/**
	* @var RuleStore
	*/
	public $preNatRules=null;
	/**
	* @var RuleStore
	*/
	public $postNatRules=null;
    /**
     * @var RuleStore
     */
    public $preDecryptionRules=null;
    /**
     * @var RuleStore
     */
    public $postDecryptionRules=null;


	/**
	* @var Array
	*/
	private $devices = Array();

	
	
	public function DeviceGroup($owner)
	{
		$this->owner = $owner;
        $this->version = &$owner->version;

		$this->device = Array();
		
		$this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';
        $this->tagStore->setCentralStoreRole(true);

		$this->zoneStore = $owner->zoneStore;
		$this->appStore = $owner->appStore;
		
		$this->serviceStore = new ServiceStore($this,true);
		$this->serviceStore->name = 'services';
		
		$this->addressStore = new AddressStore($this,true);
		$this->addressStore->name = 'addresss';
		
		$this->preNatRules = new RuleStore($this);
		$this->preNatRules->setStoreRole(true,"NatRule", true);
		
		$this->postNatRules = new RuleStore($this);
		$this->postNatRules->setStoreRole(true,"NatRule", false);
		
		$this->preSecurityRules = new RuleStore($this);
		$this->preSecurityRules->setStoreRole(true,"SecurityRule", true);
		
		$this->postSecurityRules = new RuleStore($this);
		$this->postSecurityRules->setStoreRole(true,"SecurityRule", false);

        $this->preDecryptionRules = new RuleStore($this);
        $this->preDecryptionRules->setStoreRole(true,"DecryptionRule", true);

        $this->postDecryptionRules= new RuleStore($this);
        $this->postDecryptionRules->setStoreRole(true,"DecryptionRule", false);

	}

	public function load_from_templateXml()
	{
		if( $this->owner === null )
			derr('cannot be used if owner === null');

		$fragment = $this->owner->xmlroot->ownerDocument->createDocumentFragment();

		if( ! $fragment->appendXML(self::$templatexml) )
			derr('error occured while loading device group template xml');

		$element = $this->owner->devicegrouproot->appendChild($fragment);

		$this->load_from_domxml($element);
	}


	/**
	* !! Should not be used outside of a PanoramaConf constructor. !!
	*
	*/
	public function load_from_domxml( $xml)
	{
		$this->xmlroot = $xml;
		
		// this VirtualSystem has a name ?
		$this->name = DH::findAttribute('name', $xml);
		if( $this->name === FALSE )
			derr("VirtualSystem name not found\n");

        //
        // Extract Tag objects
        //
        if( $this->owner->version >= 60 )
        {
            $tmp = DH::findFirstElementOrCreate('tag', $xml);
            $this->tagStore->load_from_domxml($tmp);
        }
        // End of Tag objects extraction


		//
		// Extract address objects 
		//
		$tmp = DH::findFirstElementOrCreate('address', $xml);
		$this->addressStore->load_addresses_from_domxml($tmp);
		//print "VirtualSystem '".$this->name."' address objectsloaded\n" ;
		// End of address objects extraction
		
		
		//
		// Extract address groups in this DV
		//
		$tmp = DH::findFirstElementOrCreate('address-group', $xml);
		$this->addressStore->load_addressgroups_from_domxml($tmp);
		//print "VirtualSystem '".$this->name."' address groups loaded\n" ;
		// End of address groups extraction
		
		
		
		//												//
		// Extract service objects in this VirtualSystem			//
		//												//
		$tmp = DH::findFirstElementOrCreate('service', $xml);
		$this->serviceStore->load_services_from_domxml($tmp);
		//print "VirtualSystem '".$this->name."' service objects\n" ;
		// End of <service> extraction
		
		
		
		//												//
		// Extract service groups in this VirtualSystem			//
		//												//
		$tmp = DH::findFirstElementOrCreate('service-group', $xml);
		$this->serviceStore->load_servicegroups_from_domxml($tmp);
		//print "VirtualSystem '".$this->name."' service groups loaded\n" ;
		// End of <service-group> extraction
		
		
		
		$prerulebase = DH::findFirstElementOrCreate('pre-rulebase', $xml);
		$postrulebase = DH::findFirstElementOrCreate('post-rulebase', $xml);

		$tmp = DH::findFirstElementOrCreate('security', $prerulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$this->preSecurityRules->load_from_domxml($tmp);

		$tmp = DH::findFirstElementOrCreate('security', $postrulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$this->postSecurityRules->load_from_domxml($tmp);


		$tmp = DH::findFirstElementOrCreate('nat', $prerulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$this->preNatRules->load_from_domxml($tmp);

		$tmp = DH::findFirstElementOrCreate('nat', $postrulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$this->postNatRules->load_from_domxml($tmp);


		// Devices extraction
		$this->devicesRoot = DH::findFirstElementOrCreate('devices', $xml);

		foreach( $this->devicesRoot->childNodes as $device )
		{
			if( $device->nodeType != 1 ) continue;
			$devname = DH::findAttribute('name', $device);
			$vsyslist = Array();

			$vsysChild = DH::firstChildElement($device);

			if( $vsysChild !== FALSE )
			{
				foreach( $vsysChild->childNodes as $vsysentry)
				{
					if( $vsysentry->nodeType != 1) continue;
					$vname = DH::findAttribute('name', $vsysentry);
					$vsyslist[] = $vname;
				}
			}
			else
			{
				//print "No vsys for device '$devname'\n";
				$vsyslist[] = 'vsys1';
			}

			$this->devices[] = Array('serial' => $devname, 'vsyslist' => $vsyslist );
		}
	}

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='".$this->name."']";

        return $str;
    }



	public function getDevicesInGroup()
	{
		return $this->devices;
	}
	
	public function name()
	{
		return $this->name;
	}

	public function setName($newName)
	{
		$this->xmlroot->setAttribute('name', $newName);

		$this->name = $newName;
	}

	public function isDeviceGroup()
	{
		return true;
	}
	
	
	
}


