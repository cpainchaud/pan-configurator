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


    /** @var AppStore */
    public $appStore;

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

    /** @var RuleStore */
    public $captivePortalRules;

    /** @var RuleStore */
    public $authenticationRules;

    /** @var RuleStore */
    public $pbfRules;

    /** @var RuleStore */
    public $qosRules;

    /** @var RuleStore */
    public $dosRules;

    /**
     * @var null|DeviceGroup
     */
    public $parentDeviceGroup = null;

    /** @var DeviceGroup[] */
    public $_childDeviceGroups = Array();

	/** @var Array */
	private $devices = Array();

    /** @var NetworkPropertiesContainer */
    public $_fakeNetworkProperties;

    public $version = null;
	
	
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
        $this->captivePortalRules = new RuleStore($this, 'CaptivePortalRule', true);
        $this->authenticationRules = new RuleStore($this, 'AuthenticationRule', true);
        $this->pbfRules = new RuleStore($this, 'PbfRule', true);
        $this->qosRules = new RuleStore($this, 'QoSRule', true);
        $this->dosRules = new RuleStore($this, 'DoSRule', true);

        $this->_fakeNetworkProperties = $this->owner->_fakeNetworkProperties;
        $this->dosRules->_networkStore = $this->_fakeNetworkProperties;
        $this->pbfRules->_networkStore = $this->_fakeNetworkProperties;
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
            $tmp = DH::findFirstElement('tag', $xml);
            if( $tmp !== false )
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

        //
        // Extract application
        //
        $tmp = DH::findFirstElementOrCreate('application', $xml);
        $this->appStore->load_application_custom_from_domxml($tmp);
        // End of application extraction

        //
        // Extract application filter
        //
        $tmp = DH::findFirstElementOrCreate('application-filter', $xml);
        $this->appStore->load_application_filter_from_domxml($tmp);
        // End of application filter groups extraction

        //
        // Extract application groups
        //
        $tmp = DH::findFirstElementOrCreate('application-group', $xml);
        $this->appStore->load_application_group_from_domxml($tmp);
        // End of application groups extraction


        //
        // Extracting policies
        //
		$prerulebase = DH::findFirstElement('pre-rulebase', $xml);
		$postrulebase = DH::findFirstElement('post-rulebase', $xml);

        if( $prerulebase === false )
            $tmp = null;
		else
        {
            $tmp = DH::findFirstElement('security', $prerulebase);
		    if( $tmp !== false )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === false )
                $tmp = null;
        }
        if( $postrulebase === false )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('security', $postrulebase);
            if( $tmpPost !== false )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === false )
                $tmpPost = null;
        }
		$this->securityRules->load_from_domxml($tmp, $tmpPost);



        if( $prerulebase === false )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('nat', $prerulebase);
            if( $tmp !== false )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === false )
                $tmp = null;
        }
        if( $postrulebase === false )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('nat', $postrulebase);
            if( $tmpPost !== false )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === false )
                $tmpPost = null;
        }
		$this->natRules->load_from_domxml($tmp, $tmpPost);





        if( $prerulebase === false )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('decryption', $prerulebase);
            if( $tmp !== false )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === false )
                $tmp = null;
        }
        if( $postrulebase === false )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('decryption', $postrulebase);
            if( $tmpPost !== false )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === false )
                $tmpPost = null;
        }
		$this->decryptionRules->load_from_domxml($tmp, $tmpPost);



        if( $prerulebase === false )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('application-override', $prerulebase);
            if( $tmp !== false )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === false )
                $tmp = null;
        }
        if( $postrulebase === false )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('application-override', $postrulebase);
            if( $tmpPost !== false )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === false )
                $tmpPost = null;
        }
        $this->appOverrideRules->load_from_domxml($tmp, $tmpPost);



        if( $prerulebase === false )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('captive-portal', $prerulebase);
            if( $tmp !== false )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === false )
                $tmp = null;
        }
        if( $postrulebase === false )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('captive-portal', $postrulebase);
            if( $tmpPost !== false )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === false )
                $tmpPost = null;
        }
        $this->captivePortalRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === false )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('authentication', $prerulebase);
            if( $tmp !== false )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === false )
                $tmp = null;
        }
        if( $postrulebase === false )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('authenticaiton', $postrulebase);
            if( $tmpPost !== false )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === false )
                $tmpPost = null;
        }
        $this->authenticationRules->load_from_domxml($tmp, $tmpPost);



        if( $prerulebase === false )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('pbf', $prerulebase);
            if( $tmp !== false )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === false )
                $tmp = null;
        }
        if( $postrulebase === false )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('pbf', $postrulebase);
            if( $tmpPost !== false )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === false )
                $tmpPost = null;
        }
        $this->pbfRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === false )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('qos', $prerulebase);
            if( $tmp !== false )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === false )
                $tmp = null;
        }
        if( $postrulebase === false )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('qos', $postrulebase);
            if( $tmpPost !== false )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === false )
                $tmpPost = null;
        }
        $this->qosRules->load_from_domxml($tmp, $tmpPost);


        if( $prerulebase === false )
            $tmp = null;
        else
        {
            $tmp = DH::findFirstElement('dos', $prerulebase);
            if( $tmp !== false )
                $tmp = DH::findFirstElement('rules', $tmp);

            if( $tmp === false )
                $tmp = null;
        }
        if( $postrulebase === false )
            $tmpPost = null;
        else
        {
            $tmpPost = DH::findFirstElement('dos', $postrulebase);
            if( $tmpPost !== false )
                $tmpPost = DH::findFirstElement('rules', $tmpPost);

            if( $tmpPost === false )
                $tmpPost = null;
        }
        $this->dosRules->load_from_domxml($tmp, $tmpPost);
        //
        // end of policies extraction
        //


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


    /**
     * @param bool $includeSubDeviceGroups look for device inside sub device-groups
     * @return array
     */
	public function getDevicesInGroup($includeSubDeviceGroups = false)
	{
		$devices = $this->devices;

		if( $includeSubDeviceGroups )
        {
            foreach( $this->_childDeviceGroups as $childDG )
            {
                $subDevices = $childDG->getDevicesInGroup(true);
                foreach( $subDevices as $subDevice )
                {
                    $serial = $subDevice['serial'];

                    if( isset($devices[$serial]) )
                    {
                        foreach($subDevice['vsyslist'] as $vsys)
                        {
                            $devices[$serial]['vsyslist'][$vsys] = $vsys;
                        }
                    }
                    else
                        $devices[$serial] = $subDevice;
                }
            }
        }

		return $devices;
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
        print "- {$this->qosRules->countPreRules()} / {$this->qosRules->countPostRules()} pre/post QoS rules\n";
        print "- {$this->pbfRules->countPreRules()} / {$this->pbfRules->countPostRules()} pre/post PBF rules\n";
        print "- {$this->decryptionRules->countPreRules()} / {$this->decryptionRules->countPostRules()} pre/post Decrypt rules\n";
        print "- {$this->appOverrideRules->countPreRules()} / {$this->appOverrideRules->countPostRules()} pre/post AppOverride rules\n";
        print "- {$this->captivePortalRules->countPreRules()} / {$this->captivePortalRules->countPostRules()} pre/post Captive Portal rules\n";
        print "- {$this->authenticationRules->countPreRules()} / {$this->authenticationRules->countPostRules()} pre/post Authentication rules\n";
        print "- {$this->dosRules->countPreRules()} / {$this->dosRules->countPostRules()} pre/post DoS rules\n";

        print "- {$this->addressStore->count()}/{$this->addressStore->countAddresses()}/{$this->addressStore->countAddressGroups()}/{$this->addressStore->countTmpAddresses()}/{$this->addressStore->countUnused()} total/address/group/tmp/unused objects\n";
        print "- {$this->serviceStore->count()}/{$this->serviceStore->countServices()}/{$this->serviceStore->countServiceGroups()}/{$this->serviceStore->countTmpServices()}/{$this->serviceStore->countUnused()} total/service/group/tmp/unused objects\n";
        print "- {$this->tagStore->count()} tags. {$this->tagStore->countUnused()} unused\n";
	}

    /**
     * @param bool $nested
     * @return DeviceGroup[]
     */
	public function childDeviceGroups($nested = false)
    {
        if( $nested )
        {
            $dgs = Array();

            foreach( $this->_childDeviceGroups as $dg )
            {
                $dgs[$dg->name()] = $dg;
                $tmp = $dg->childDeviceGroups(true);
                foreach( $tmp as $sub )
                    $dgs[$sub->name()] = $sub;
            }

            return $dgs;
        }

        return $this->_childDeviceGroups;
    }

    /**
     * @return DeviceGroup[]
     */
    public function parentDeviceGroups()
    {
        if( $this->name() == 'shared' )
        {
            $dgs[$this->name()] = $this;
            return $dgs;
        }

        $dg_tmp = $this;
        $dgs = Array();

        while( $dg_tmp !== null )
        {
            $dgs[$dg_tmp->name()] = $dg_tmp;
            $dg_tmp = $dg_tmp->parentDeviceGroup;
        }

        return $dgs;
    }

}


