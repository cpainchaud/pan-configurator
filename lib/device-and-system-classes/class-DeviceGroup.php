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


class DeviceGroup 
{
	
	use PathableName;
	use PanSubHelperTrait;

	/** String */
	protected $name;

    /** @var PanoramaConf */
	public $owner = null;

	/** @var DOMElement */
	public $xmlroot;

    /** @var DOMElement */
    public $devicesRoot;

    /** @var AddressStore */
    public $addressStore=null;
    /** @var ServiceStore */
    public $serviceStore=null;

	public static $templatexml = '<entry name="**Need a Name**"><address></address><post-rulebase><security><rules></rules></security><nat><rules></rules></nat></post-rulebase>
									<pre-rulebase><security><rules></rules></security><nat><rules></rules></nat></pre-rulebase>
									</entry>';

	
	/** @var TagStore */
	public $tagStore=null;
	
	/** @var ZoneStore */
	public $zoneStore=null;

	/** @var RuleStore */
	public $securityRules=null;

	/** @var RuleStore */
	public $natRules=null;

    /** @var RuleStore */
    public $decryptionRules=null;

    /** @var RuleStore */
    public $appOverrideRules;

    /**
     * @var null|DeviceGroup
     */
    public $parentDeviceGroup = null;

    /** @var DeviceGroup[] */
    public $childDeviceGroups = Array();


	/** @var Array */
	private $devices = Array();

	
	
	public function __construct($owner)
	{
		$this->owner = $owner;
        $this->version = &$owner->version;

		$this->device = Array();
		
		$this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';

		$this->zoneStore = $owner->zoneStore;
		$this->appStore = $owner->appStore;
		
		$this->serviceStore = new ServiceStore($this);
		$this->serviceStore->name = 'services';
		
		$this->addressStore = new AddressStore($this);
		$this->addressStore->name = 'addresss';

		$this->securityRules = new RuleStore($this, 'SecurityRule', true);
		$this->natRules = new RuleStore($this, 'NatRule', true);
		$this->decryptionRules = new RuleStore($this, 'DecryptionRule', true);
        $this->appOverrideRules = new RuleStore($this, 'AppOverrideRule', true);

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
	* @param DOMElement $xml
	*/
	public function load_from_domxml( $xml )
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
		$tmpPost = DH::findFirstElementOrCreate('security', $postrulebase);
		$tmpPost = DH::findFirstElementOrCreate('rules', $tmpPost);
		$this->securityRules->load_from_domxml($tmp, $tmpPost);

		$tmp = DH::findFirstElementOrCreate('nat', $prerulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$tmpPost = DH::findFirstElementOrCreate('nat', $postrulebase);
		$tmpPost = DH::findFirstElementOrCreate('rules', $tmpPost);
		$this->natRules->load_from_domxml($tmp, $tmpPost);


		$tmp = DH::findFirstElementOrCreate('decryption', $prerulebase);
		$tmp = DH::findFirstElementOrCreate('rules', $tmp);
		$tmpPost = DH::findFirstElementOrCreate('decryption', $postrulebase);
		$tmpPost = DH::findFirstElementOrCreate('rules', $tmpPost);
		$this->decryptionRules->load_from_domxml($tmp, $tmpPost);


        $tmp = DH::findFirstElementOrCreate('application-override', $prerulebase);
        $tmp = DH::findFirstElementOrCreate('rules', $tmp);
        $tmpPost = DH::findFirstElementOrCreate('application-override', $postrulebase);
        $tmpPost = DH::findFirstElementOrCreate('rules', $tmpPost);
        $this->appOverrideRules->load_from_domxml($tmp, $tmpPost);


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
					$vsyslist[$vname] = $vname;
				}
			}
			else
			{
				//print "No vsys for device '$devname'\n";
				$vsyslist['vsys1'] = 'vsys1';
			}

			$this->devices[$devname] = Array('serial' => $devname, 'vsyslist' => $vsyslist );
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


	public function display_statistics()
	{
		print "Statistics for DG '".PH::boldText($this->name)."'\n";
        print "- {$this->securityRules->countPreRules()} / {$this->securityRules->countPostRules()} pre/post Security rules\n";
        print "- {$this->natRules->countPreRules()} / {$this->natRules->countPostRules()} pre/post Nat rules\n";
        print "- {$this->decryptionRules->countPreRules()} / {$this->decryptionRules->countPostRules()} pre/post Decrypt rules\n";
        print "- {$this->appOverrideRules->countPreRules()} / {$this->appOverrideRules->countPostRules()} pre/post AppOverride rules\n";
		print "- {$this->addressStore->countAddresses()} / {$this->addressStore->countAddressGroups()} / {$this->addressStore->countTmpAddresses()} address/group/tmp/total objects\n";
		print "- {$this->serviceStore->countServices()} / {$this->serviceStore->countServiceGroups()} / {$this->serviceStore->countTmpServices()} service/group/tmp/total objects\n";
		print "- {$this->tagStore->count()} tags. {$this->tagStore->countUnused()} unused\n";
	}
	
	
	
}


