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

/**
 * Your journey will start from PANConf or PanoramaConf
 *
 * Code:
 *
 *  $pan = new PanoramaConf();
 *
 *  $pan->load_from_file('config.txt');
 *
 *  $pan->display_statistics();
 *
 * And there you go !
 *
 */
class PanoramaConf
{
	use PathableName;
	use centralTagStore;
	use centralAppStore;
	use PanSubHelperTrait;


    /** @var DOMElement */
	public $xmlroot;

    /** @var DOMElement */
	public $sharedroot;
	public $devicesroot;
	public $localhostlocaldomain;

    /** @var string[]|DomNode */
	public $devicegrouproot;


    public $version = null;

	protected $managedFirewallsSerials = Array();

    /** @var DeviceGroup[] */
	public $deviceGroups = Array();

    /** @var Template[]  */
    public $templates = Array();

    /** @var RuleStore */
	public $securityRules;

    /** @var RuleStore */
	public $natRules;

    /** @var RuleStore */
    public $decryptionRules=null;

    /** @var RuleStore */
    public $appOverrideRules;

    /** @var AddressStore */
    public $addressStore=null;

    /** @var ServiceStore */
    public $serviceStore=null;

    /** @var ZoneStore */
    public $zoneStore=null;


    /** @var PanAPIConnector|null */
	public $connector = null;
	
	public $name = '';

	public function name()
	{
		return $this->name;
	}
	
	public function __construct()
	{
		$this->tagStore = new TagStore($this);
		$this->tagStore->setName('tagStore');
		
		$this->zoneStore = new ZoneStore($this);
		$this->zoneStore->setName('zoneStore');
		
		$this->appStore = AppStore::getPredefinedStore();
		
		$this->serviceStore = new ServiceStore($this);
		$this->serviceStore->name = 'services';
		
		$this->addressStore = new AddressStore($this);
		$this->addressStore->name = 'addresses';


		$this->securityRules = new RuleStore($this, 'SecurityRule', true);
		$this->natRules = new RuleStore($this, 'NatRule', true);
		$this->decryptionRules = new RuleStore($this, 'DecryptionRule', true);
        $this->appOverrideRules = new RuleStore($this, 'AppOverrideRule', true);
	}


	public function load_from_xmlstring(&$xml)
	{
		$this->xmldoc = new DOMDocument();

		if( $this->xmldoc->loadXML($xml) !== TRUE )
			derr('Invalid XML file found');

		$this->load_from_domxml($this->xmldoc);
	}

    /**
     * @param $xml DOMNode
     * @throws Exception
     */
	public function load_from_domxml($xml)
	{

        if( $xml->nodeType == XML_DOCUMENT_NODE )
        {
            $this->xmldoc = $xml;
            $this->configroot = DH::findFirstElementOrDie('config', $this->xmldoc);
            $this->xmlroot = $this->configroot;
        }
        else
        {
            $this->xmldoc = $xml->ownerDocument;
            $this->configroot = $xml;
            $this->xmlroot = $xml;
        }

		$versionAttr = DH::findAttribute('version', $this->configroot);
		if( $versionAttr !== false )
		{
			$this->version = PH::versionFromString($versionAttr);
		}
		else
		{
			if( isset($this->connector) && $this->connector !== null )
				$version = $this->connector->getSoftwareVersion();
			else
				derr('cannot find PANOS version used for make this config');

			$this->version = $version['version'];
		}


		$tmp = DH::findFirstElementOrCreate('mgt-config', $this->configroot);

		$tmp = DH::findFirstElementOrCreate('devices', $tmp);

		foreach( $tmp->childNodes as $serial )
		{
			if( $serial->nodeType != 1 )
				continue;
			$s = DH::findAttribute('name', $serial);
			if( $s === FALSE )
				derr('no serial found');

			$this->managedFirewallsSerials[] = $s;
		}

		$this->sharedroot = DH::findFirstElementOrDie('shared', $this->configroot);

		$this->devicesroot = DH::findFirstElementOrDie('devices', $this->configroot);

		$this->localhostroot = DH::findFirstElementByNameAttrOrDie('entry', 'localhost.localdomain',$this->devicesroot);

		$this->devicegrouproot = DH::findFirstElementOrDie('device-group', $this->localhostroot);
        $this->templateroot = DH::findFirstElementOrDie('template', $this->localhostroot);

        //
        // Extract Tag objects
        //
        if( $this->version >= 60 )
        {
            $tmp = DH::findFirstElementOrCreate('tag', $this->sharedroot);
            $this->tagStore->load_from_domxml($tmp);
        }
        // End of Tag objects extraction


		//
		// Shared address objects extraction
		//
		$tmp = DH::findFirstElementOrCreate('address', $this->sharedroot);
		$this->addressStore->load_addresses_from_domxml($tmp);
		// end of address extraction

		//
		// Extract address groups 
		//
		$tmp = DH::findFirstElementOrCreate('address-group', $this->sharedroot);
		$this->addressStore->load_addressgroups_from_domxml($tmp);
		// End of address groups extraction

		//
		// Extract services
		//
		$tmp = DH::findFirstElementOrCreate('service', $this->sharedroot);
		$this->serviceStore->load_services_from_domxml($tmp);
		// End of address groups extraction

		//
		// Extract service groups 
		//
		$tmp = DH::findFirstElementOrCreate('service-group', $this->sharedroot);
		$this->serviceStore->load_servicegroups_from_domxml($tmp);
		// End of address groups extraction

		$prerulebase = DH::findFirstElementOrCreate('pre-rulebase', $this->sharedroot);
		$postrulebase = DH::findFirstElementOrCreate('post-rulebase', $this->sharedroot);

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


        //
        // loading templates
        //
        foreach ($this->templateroot->childNodes as $node)
        {
            if ($node->nodeType != XML_ELEMENT_NODE) continue;

            $ldv = new Template('*tmp*', $this);
            $ldv->load_from_domxml($node);
            $this->templates[] = $ldv;
            //print "Template '{$ldv->name()}' found\n";
        }
        //
        // end of Templates
        //


        //
		// loading Device Groups now
        //
        if( $this->version < 70 )
        {
            foreach ($this->devicegrouproot->childNodes as $node)
            {
                if ($node->nodeType != XML_ELEMENT_NODE) continue;
                $lvname = $node->nodeName;
                //print "Device Group '$lvname' found\n";

                $ldv = new DeviceGroup($this);
                $ldv->load_from_domxml($node);
                $this->deviceGroups[] = $ldv;
            }
        }
        else
        {
            $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dginfo', $this->xmlroot);

            $dgToParent = Array();
            $parentToDG = Array();

            foreach( $dgMetaDataNode->childNodes as $node )
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $dgName = DH::findAttribute('name',$node);
                if( $dgName === false )
                    derr("DeviceGroup name attribute not found in dg-meta-data", $node);

                $parentDG = DH::findFirstElement('parent-dg', $node);
                if( $parentDG === false )
                {
                    $dgToParent[$dgName] = 'shared';
                    $parentToDG['shared'][] = $dgName;
                }
                else
                {
                    $dgToParent[$dgName] = $parentDG->textContent;
                    $parentToDG[$parentDG->textContent][] = $dgName;
                }
            }

            $dgLoadOrder = Array('shared');


            while( count($parentToDG) > 0 )
            {
                $dgLoadOrderCount = count($dgLoadOrder);

                foreach( $dgLoadOrder as &$dgName )
                {
                    if( isset($parentToDG[$dgName]) )
                    {
                        foreach($parentToDG[$dgName] as &$newDGName )
                        {
                            $dgLoadOrder[] = $newDGName;
                        }
                        unset($parentToDG[$dgName]);
                    }
                }

                if( count($dgLoadOrder) <= $dgLoadOrderCount )
                    derr('dg-meta-data seems to be corrupted, parent.child template cannot be calculated ', $dgMetaDataNode);

                $dgLoadOrderCount = count($dgLoadOrder);
            }

            /*print "DG loading order:\n";
            foreach( $dgLoadOrder as &$dgName )
                print " - {$dgName}\n";*/


            $deviceGroupNodes = Array();

            foreach ($this->devicegrouproot->childNodes as $node)
            {
                if( $node->nodeType != XML_ELEMENT_NODE )
                    continue;

                $nodeNameAttr = DH::findAttribute('name', $node);
                if( $nodeNameAttr === false )
                    derr("DeviceGroup 'name' attribute was not found", $node);

                if( !is_string($nodeNameAttr) || $nodeNameAttr == '' )
                    derr("DeviceGroup 'name' attribute has invalid value", $node);

                $deviceGroupNodes[$nodeNameAttr] = $node;
            }

            foreach( $dgLoadOrder as $dgIndex => &$dgName )
            {
                if( $dgName == 'shared' )
                    continue;

                if( !isset($deviceGroupNodes[$dgName]) )
                {
                    mwarning("DeviceGroup '$dgName' is listed in dg-meta-data but doesn't exist in XML");
                    //unset($dgLoadOrder[$dgIndex]);
                    continue;
                }

                $ldv = new DeviceGroup($this);
                if( !isset($dgToParent[$dgName]) )
                {
                    mwarning("DeviceGroup '$dgName' has not parent associated, assuming SHARED");
                }
                elseif( $dgToParent[$dgName] == 'shared' )
                {
                    // do nothing
                }
                else
                {
                    $parentDG = $this->findDeviceGroup($dgToParent[$dgName]);
                    if( $parentDG === null )
                        mwarning("DeviceGroup '$dgName' has DG '{$dgToParent[$dgName]}' listed as parent but it cannot be found in XML");
                    else
                    {
                        $parentDG->childDeviceGroups[$dgName] = $ldv;
                        $ldv->parentDeviceGroup = $parentDG;
                    }
                }

                $ldv->load_from_domxml($deviceGroupNodes[$dgName]);
                $this->deviceGroups[] = $ldv;

            }

        }
        //
        // End of DeviceGroup loading
        //

	}


    /**
     * @param string $name
     * @return DeviceGroup|null
     */
	public function findDeviceGroup($name)
	{
		foreach($this->deviceGroups as $dg )
        {
			if( $dg->name() == $name )
				return $dg;
		}

		return null;
	}

    /**
     * @param string $name
     * @return Template|null
     */
    public function findTemplate($name)
    {
        foreach($this->templates as $template )
        {
            if( $template->name() == $name )
                return $template;
        }

        return null;
    }


    /**
     * @param string $fileName
     * @param bool $printMessage
     * @param int $indentingXml
     */
	public function save_to_file($fileName, $printMessage=true, $indentingXml = 1)
	{
        if($printMessage)
            print "Now saving PANConf to file '$fileName'...";

        $xml = &DH::dom_to_xml($this->xmlroot, 0, true, -1, 2 );
        file_put_contents ( $fileName , $xml);

        if($printMessage)
            print "     done!\n\n";
	}

    /**
     * @param string $fileName
     */
	public function load_from_file($fileName)
	{
		$filecontents = file_get_contents($fileName);

		$this->load_from_xmlstring($filecontents);

	}
	
	
	public function display_statistics()
	{

		$gpreSecRules = $this->securityRules->countPreRules();
		$gpreNatRules = $this->natRules->countPreRules();
        $gpreDecryptRules = $this->decryptionRules->countPreRules();

		$gpostSecRules = $this->securityRules->countPostRules();
		$gpostNatRules = $this->natRules->countPostRules();
        $gpostDecryptRules = $this->decryptionRules->countPostRules();

		$gnservices = $this->serviceStore->countServices();
		$gnservicesUnused = $this->serviceStore->countUnusedServices();
		$gnserviceGs = $this->serviceStore->countServiceGroups();
		$gnserviceGsUnused = $this->serviceStore->countUnusedServiceGroups();
		$gnTmpServices = $this->serviceStore->countTmpServices();

		$gnaddresss = $this->addressStore->countAddresses();
		$gnaddresssUnused = $this->addressStore->countUnusedAddresses();
		$gnaddressGs = $this->addressStore->countAddressGroups();
		$gnaddressGsUnused = $this->addressStore->countUnusedAddressGroups();
		$gnTmpAddresses = $this->addressStore->countTmpAddresses();

		foreach( $this->deviceGroups as $cur)
		{
			$gpreSecRules += $cur->securityRules->countPreRules();
			$gpreNatRules += $cur->natRules->countPreRules();
            $gpreDecryptRules += $cur->decryptionRules->countPreRules();

			$gpostSecRules += $cur->securityRules->countPostRules();
			$gpostNatRules += $cur->natRules->countPostRules();
            $gpostDecryptRules += $cur->decryptionRules->countPostRules();

			$gnservices += $cur->serviceStore->countServices();
			$gnservicesUnused += $cur->serviceStore->countUnusedServices();
			$gnserviceGs += $cur->serviceStore->countServiceGroups();
			$gnserviceGsUnused += $cur->serviceStore->countUnusedServiceGroups();
			$gnTmpServices += $cur->serviceStore->countTmpServices();

			$gnaddresss += $cur->addressStore->countAddresses();
			$gnaddresssUnused += $cur->addressStore->countUnusedAddresses();
			$gnaddressGs += $cur->addressStore->countAddressGroups();
			$gnaddressGsUnused += $cur->addressStore->countUnusedAddressGroups();
			$gnTmpAddresses += $cur->addressStore->countTmpAddresses();
		}
		
		print "Statistics for PanoramaConf '".$this->name."'\n";
		print "- ".$this->securityRules->countPreRules()." (".$gpreSecRules.") pre-SecRules\n";
		print "- ".$this->securityRules->countPostRules()." (".$gpostSecRules.") post-SecRules\n";

		print "- ".$this->natRules->countPreRules()." (".$gpreNatRules.") pre-NatRules\n";
		print "- ".$this->natRules->countPostRules()." (".$gpostNatRules.") post-NatRules\n";

        print "- ".$this->decryptionRules->countPreRules()." (".$gpreDecryptRules.") pre-NatRules\n";
        print "- ".$this->decryptionRules->countPostRules()." (".$gpostDecryptRules.") post-NatRules\n";

		print "- ".$this->addressStore->countAddresses()." (".$gnaddresss.") address objects. {$gnaddresssUnused} unused\n";

		print "- ".$this->addressStore->countAddressGroups()." (".$gnaddressGs.") address groups. {$gnaddressGsUnused} unused\n";

		print "- ".$this->serviceStore->countServices()." (".$gnservices.") service objects. {$gnservicesUnused} unused\n";

		print "- ".$this->serviceStore->countServiceGroups()." (".$gnserviceGs.") service groups. {$gnserviceGsUnused} unused\n";

		print "- ".$this->addressStore->countTmpAddresses()." (".$gnTmpAddresses.") temporary address objects\n";

		print "- ".$this->serviceStore->countTmpServices()." (".$gnTmpServices.") temporary service objects\n";
		
		print "- ".$this->zoneStore->count()." zones\n";
		print "- ".$this->tagStore->count()." tags\n";
	}

    public function API_load_from_running( PanAPIConnector $conn )
    {
        $this->connector = $conn;

		$xmlDoc = $this->connector->getRunningConfig();
		$this->load_from_domxml($xmlDoc);
    }

    public function API_load_from_candidate( PanAPIConnector $conn )
    {
        $this->connector = $conn;

		$xmlDoc = $this->connector->getCandidateConfig();
		$this->load_from_domxml($xmlDoc);
    }

	/**
	* send current config to the firewall and save under name $config_name
	*
	*/
	public function API_uploadConfig( $config_name = 'panconfigurator-default.xml' )
	{
		print "Uploadig config to device....";

		$url = "&type=import&category=configuration&category=configuration";

		$answer = &$this->connector->sendRequest($url, false, DH::dom_to_xml($this->xmlroot), $config_name );


		print "OK!\n";
	}

	/**
	*	load all managed firewalls configs from API from running config if $fromRunning = TRUE
	*/
	public function API_loadManagedFirewallConfigs($fromRunning)
	{
		$this->managedFirewalls = Array();

		derr('not implemented yet');
	}

	/**
	*	load all managed firewalls configs from a directory
	*/
	public function loadManagedFirewallsConfigs($fromDirectory = './')
	{
		$this->managedFirewalls = Array();

		$files = scandir($fromDirectory);

		foreach( $this->managedFirewallsSerials as &$serial )
		{
			$fw = FALSE;
			foreach( $files as &$file )
			{
				$pos = strpos($file, $serial);
				if( $pos !== FALSE )
				{
					//$fc = file_get_contents($file);
					//if( $fc === FALSE )
					//	derr("could not open file '$file'");

					print "Loading FW '$serial' from file '$file'.\n";

					$fw = new PANConf($this, $serial);
					$fw->load_from_file($fromDirectory.'/'.$file);
					$this->managedFirewalls[] = $fw;
					break;
				}

			}
			if( $fw === FALSE )
			{
				derr("couldn't find a suitable file to load for FW '$serial'");
			}
		}

		//derr('not implemented yet');
	}


    /**
     * @param string $deviceSerial
     * @param string $vsysName
     * @return DeviceGroup|bool
     */
	public function findApplicableDGForVsys($deviceSerial , $vsysName)
	{
		if( is_null($deviceSerial) || strlen($deviceSerial) < 1 )
			derr('invalid serial provided!');
		if( is_null($vsysName) || strlen($vsysName) < 1 )
			derr('invalid serial provided!');

		//print "looking for serial $deviceSerial  and vsys $vsysName\n";

		foreach( $this->deviceGroups as $dv )
		{
			$ds = $dv->getDevicesInGroup();
			foreach($ds as &$d)
			{
				if( $d['serial'] == $deviceSerial )
				{
					//print "serial found\n";
					if( array_search($vsysName, $d['vsyslist'])!== FALSE )
					{
						//print "match!\n";
						return $dv;
					}
				}
			}
		}

		return false;
	}

	/**
	* Create a blank device group. Return that DV object.
	**/
	public function createDeviceGroup($newDV_Name)
	{
		$newDG = new DeviceGroup($this);
		$newDG->load_from_templateXml();

		$newDG->setName($newDV_Name);

		return $newDG;

	}

    /**
     * @return DeviceGroup[]
     */
    public function getDeviceGroups()
    {
        return $this->deviceGroups;
    }

	public function isPanorama()
	{
		return true;
	}

    public function findSubSystemByName($location)
    {
        return $this->findDeviceGroup($location);
    }

}



