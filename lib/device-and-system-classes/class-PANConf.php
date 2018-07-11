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
 * Your journey will start from PANConf or PanoramaConf
 *
 * Code:
 *
 *  $pan = new PANConf();
 *
 *  $pan->load_from_file('config.txt');
 *
 *  $vsys1 = $pan->findVirtualSystem('vsys1');
 *
 *  $vsys1->display_statistics();
 *
 * And there you go !
 *
 */
class PANConf
{
	
	use PathableName;
	use PanSubHelperTrait;

    /** @var DOMElement */
	public $xmlroot;

    /** @var DOMDocument */
    public $xmldoc;

    /** @var DOMElement */
	public $sharedroot;
    /** @var DOMDocument */
	public $devicesroot;
    /** @var DOMElement */
	public $localhostroot;

	/** @var DOMElement|null */
	public $vsyssroot;

	public $name = '';

    /** @var AddressStore */
    public $addressStore=null;

    /** @var ServiceStore */
    public $serviceStore=null;

    public $version = null;

    /** @var VirtualSystem[] */
	public $virtualSystems = Array();

    /** @var PanAPIConnector|null $connector */
	public $connector = null;

    /** @var null|Template  */
    public $owner = null;

	/** @var NetworkPropertiesContainer */
	public $network;

    /** @var AppStore */
    public $appStore;

    /** @var TagStore */
    public $tagStore;


	public function name()
	{
		return $this->name;
	}
	
	/**
	 * @param PanoramaConf|null $withPanorama
     * @param string|null $serial
     * @param Template|null $fromTemplate
	 */
	public function __construct($withPanorama = null, $serial = null, $fromTemplate = null)
	{
		if( $withPanorama !== null )
			$this->panorama = $withPanorama;
		if( $serial !== null )
			$this->serial = $serial;

        $this->owner = $fromTemplate;

		$this->tagStore = new TagStore($this);
		$this->tagStore->setName('tagStore');

		$this->appStore = AppStore::getPredefinedStore();

		$this->serviceStore = new ServiceStore($this);
		$this->serviceStore->name = 'services';

		$this->addressStore = new AddressStore($this);
		$this->addressStore->name = 'addresses';

		$this->network = new NetworkPropertiesContainer($this);
	}


	public function load_from_xmlstring(&$xml)
	{
		$xmlDoc = new DOMDocument();

		if ($xmlDoc->loadXML($xml, LIBXML_PARSEHUGE) !== TRUE)
			derr('Invalid XML file found');

		$this->load_from_domxml($xmlDoc);
	}

    /**
     * @param $xml DOMElement|DOMDocument
     * @throws Exception
     */
	public function load_from_domxml($xml)
	{
        if( $xml->nodeType == XML_DOCUMENT_NODE )
        {
		    $this->xmldoc = $xml;
            $this->xmlroot = DH::findFirstElementOrDie('config', $this->xmldoc);
        }
        else
            $this->xmlroot = $xml;


        if( $this->owner !== null )
        {
            $this->version = $this->owner->owner->version;
        }
        else
        {
            $versionAttr = DH::findAttribute('version', $this->xmlroot);
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
        }


		$this->devicesroot = DH::findFirstElementOrCreate('devices', $this->xmlroot);

		$this->localhostroot = DH::findFirstElement('entry', $this->devicesroot);
        if( $this->localhostroot === false )
        {
            $this->localhostroot = DH::createElement($this->devicesroot, 'entry');
            $this->localhostroot->setAttribute('name', 'localhost.localdomain');
        }

		$this->vsyssroot = DH::findFirstElementOrCreate('vsys', $this->localhostroot);



        if( $this->owner === null )
        {
            $this->sharedroot = DH::findFirstElementOrDie('shared', $this->xmlroot);
            //
            // Extract Tag objects
            //
            if( $this->version >= 60 )
            {
                $tmp = DH::findFirstElement('tag', $this->sharedroot);
                if( $tmp !== false )
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

            //
            // Extract application
            //
            $tmp = DH::findFirstElementOrCreate('application', $this->sharedroot);
            $this->appStore->load_application_custom_from_domxml($tmp);
            // End of address extraction

            //
            // Extract application filter
            //
            $tmp = DH::findFirstElementOrCreate('application-filter', $this->sharedroot);
            $this->appStore->load_application_filter_from_domxml($tmp);
            // End of application filter groups extraction

            //
            // Extract application groups
            //
            $tmp = DH::findFirstElementOrCreate('application-group', $this->sharedroot);
            $this->appStore->load_application_group_from_domxml($tmp);
            // End of address groups extraction

        }

		//
		// Extract network related configs
		//
		$tmp = DH::findFirstElementOrCreate('network', $this->localhostroot );
		$this->network->load_from_domxml($tmp);
		//
		
		
		// Now listing and extracting all VirtualSystem configurations
		foreach( $this->vsyssroot->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;
			//print "DOM type: ".$node->nodeType."\n";

			$localVirtualSystemName = DH::findAttribute('name', $node);

			if( $localVirtualSystemName === FALSE || strlen($localVirtualSystemName) < 1 )
				derr('cannot find VirtualSystem name');

            $dg = null;

			if( isset($this->panorama) )
			{
                if( $this->panorama->_fakeMode )
                    $dg = $this->panorama->findDeviceGroup($localVirtualSystemName);
				else
                    $dg = $this->panorama->findApplicableDGForVsys($this->serial , $localVirtualSystemName);
			}

            if( $dg !== false && $dg !== null )
                $localVsys = new VirtualSystem($this, $dg);
            else
                $localVsys = new VirtualSystem($this);

			$localVsys->load_from_domxml($node);
			$this->virtualSystems[] = $localVsys;

            $importedInterfaces = $localVsys->importedInterfaces->interfaces();
            foreach( $importedInterfaces as &$ifName )
            {
                $resolvedIf = $this->network->findInterface($ifName);
                if( $resolvedIf !== null )
                    $resolvedIf->importedByVSYS = $localVsys;
            }
		}


	}


    /**
     * !!OBSOLETE!!
     * @obsolete
     * @param string $name
     * @return VirtualSystem|null
     */
	public function findVSYS_by_Name($name)
	{
        mwarning('use of obsolete function, please use findVirtualSystem() instead!');
		return $this->findVirtualSystem($name);
	}

    /**
     * @param string $name
     * @return VirtualSystem|null
     */
    public function findVirtualSystem($name)
    {
        foreach( $this->virtualSystems as $vsys )
        {
            if( $vsys->name() == $name )
            {
                return $vsys;
            }
        }

        return null;
    }

    /**
     * @param string $fileName
     * @param bool $printMessage
     */
	public function save_to_file($fileName, $printMessage=true)
	{
        if($printMessage)
            print "Now saving PANConf to file '$fileName'...";

		$xml = &DH::dom_to_xml($this->xmlroot);
		file_put_contents ( $fileName , $xml);

        if($printMessage)
            print "     done!\n\n";
	}

    /**
     * @param $fileName string
     */
	public function load_from_file($fileName)
	{
		$filecontents = file_get_contents($fileName);

		$this->load_from_xmlstring($filecontents);
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

		$url = "&type=import&category=configuration";

		$this->connector->sendRequest($url, false, DH::dom_to_xml($this->xmlroot), $config_name );

		print "OK!\n";

	}

    /**
     * @return VirtualSystem[]
     */
    public function getVirtualSystems()
    {
        return $this->virtualSystems;
    }


	public function display_statistics()
	{

		$numSecRules = 0;
		$numNatRules = 0;
        $numQosRules = 0;
        $numPbfRules = 0;
		$numDecryptRules = 0;
        $numAppOverrideRules = 0;
        $numCaptivePortalRules = 0;
        $numAuthenticationRules = 0;
        $numDosRules = 0;


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

		$numInterfaces = $this->network->ipsecTunnelStore->count() + $this->network->ethernetIfStore->count();
		$numSubInterfaces = $this->network->ethernetIfStore->countSubInterfaces();

        $gTagCount = $this->tagStore->count();
        $gTagUnusedCount = $this->tagStore->countUnused();

		foreach($this->virtualSystems as $vsys )
		{

			$numSecRules += $vsys->securityRules->count();
			$numNatRules += $vsys->natRules->count();
            $numQosRules += $vsys->qosRules->count();
            $numPbfRules += $vsys->pbfRules->count();
			$numDecryptRules += $vsys->decryptionRules->count();
            $numAppOverrideRules += $vsys->appOverrideRules->count();
            $numCaptivePortalRules += $vsys->captivePortalRules->count();
            $numAuthenticationRules += $vsys->authenticationRules->count();
            $numDosRules += $vsys->dosRules->count();

			$gnservices += $vsys->serviceStore->countServices();
			$gnservicesUnused += $vsys->serviceStore->countUnusedServices();
			$gnserviceGs += $vsys->serviceStore->countServiceGroups();
			$gnserviceGsUnused += $vsys->serviceStore->countUnusedServiceGroups();
			$gnTmpServices += $vsys->serviceStore->countTmpServices();

			$gnaddresss += $vsys->addressStore->countAddresses();
			$gnaddresssUnused += $vsys->addressStore->countUnusedAddresses();
			$gnaddressGs += $vsys->addressStore->countAddressGroups();
			$gnaddressGsUnused += $vsys->addressStore->countUnusedAddressGroups();
			$gnTmpAddresses += $vsys->addressStore->countTmpAddresses();

            $gTagCount += $vsys->tagStore->count();
            $gTagUnusedCount += $vsys->tagStore->countUnused();

		}

		print "Statistics for PANConf '".$this->name."'\n";
		print "- ".$numSecRules." Security Rules\n";

		print "- ".$numNatRules." Nat Rules\n";

        print "- ".$numQosRules." Qos Rules\n";

        print "- ".$numPbfRules." Pbf Rules\n";

		print "- ".$numDecryptRules." Decryption Rules\n";

        print "- ".$numAppOverrideRules." AppOverride Rules\n";

        print "- ".$numCaptivePortalRules." CaptivePortal Rules\n";

        print "- ".$numAuthenticationRules." Authentication Rules\n";

        print "- ".$numDosRules." Dos Rules\n";

		print "- ".$this->addressStore->countAddresses()." (".$gnaddresss.") address objects. {$gnaddresssUnused} unused\n";

		print "- ".$this->addressStore->countAddressGroups()." (".$gnaddressGs.") address groups. {$gnaddressGsUnused} unused\n";

		print "- ".$this->serviceStore->countServices()." (".$gnservices.") service objects. {$gnservicesUnused} unused\n";

		print "- ".$this->serviceStore->countServiceGroups()." (".$gnserviceGs.") service groups. {$gnserviceGsUnused} unused\n";

		print "- ".$this->addressStore->countTmpAddresses()." (".$gnTmpAddresses.") temporary address objects\n";

		print "- ".$this->serviceStore->countTmpServices()." (".$gnTmpServices.") temporary service objects\n";

        print "- ".$this->tagStore->count()." (".$gTagCount.") tags. {$gTagUnusedCount} unused\n";

		print "- $numInterfaces interfaces (Ethernet:{$this->network->ethernetIfStore->count()})\n";
		print "- $numSubInterfaces sub-interfaces (Ethernet:{$this->network->ethernetIfStore->countSubInterfaces()})\n";
	}


	public function isFirewall()
	{
		return true;
	}

    public function createVirtualSystem( $vsysID, $displayName = '')
    {
        if( !is_numeric($vsysID) )
            derr("new vsys id must be an integer but '$vsysID' was provided");

        $newVsysName = 'vsys'.$vsysID;

        if( $this->findVirtualSystem($newVsysName) !== null )
            derr("cannot create '$newVsysName' because it already exists");

        $xmlNode = DH::importXmlStringOrDie($this->xmldoc, VirtualSystem::$templateXml);

        $xmlNode->setAttribute('name', $newVsysName);
        if( strlen($displayName) > 0 )
            DH::createElement($xmlNode, 'display-name', $displayName);

        $this->vsyssroot->appendChild($xmlNode);

        $newVsys = new VirtualSystem($this);
        $newVsys->load_from_domxml($xmlNode);

        $this->virtualSystems[] = $newVsys;

        return $newVsys;
    }

    public function findSubSystemByName($location)
    {
        return $this->findVirtualSystem($location);
    }

}

