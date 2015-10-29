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
	use centralTagStore;
	use PanSubHelperTrait;

    /** @var DOMElement */
	public $xmlroot;

    /** @var DOMDocument */
    public $xmldoc;
	
	public $sharedroot;
	public $devicesroot;
	public $localhostlocaldomain;

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

    /** @var PanAPIConnector|null */
	public $connector = null;

    /** @var null|Template  */
    public $owner = null;

	/** @var NetworkPropertiesContainer */
	public $network;

    /** @var AppStore */
    public $appStore;


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
		if( $withPanorama !== null )
			$this->serviceStore->panoramaShared = $this->panorama->serviceStore;

		$this->addressStore = new AddressStore($this);
		$this->addressStore->name = 'addresses';
		if( $withPanorama !== null )
			$this->addressStore->panoramaShared = $this->panorama->addressStore;

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
            $this->configroot = DH::findFirstElementOrDie('config', $this->xmldoc);
            $this->xmlroot = $this->configroot;
        }
        else
        {
            $this->xmlroot = $xml;
            $this->configroot = $xml;
        }


        if( $this->owner !== null )
        {
            $this->version = $this->owner->owner->version;
        }
        else
        {
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
        }


		$this->devicesroot = DH::findFirstElementOrCreate('devices', $this->configroot);

		$this->localhostroot = DH::findFirstElement('entry', $this->devicesroot);
        if( $this->localhostroot === false )
        {
            $this->localhostroot = DH::createElement($this->devicesroot, 'entry');
            $this->localhostroot->setAttribute('name', 'localhost.localdomain');
        }

		$this->vsyssroot = DH::findFirstElementOrCreate('vsys', $this->localhostroot);



        if( $this->owner === null )
        {
            $this->sharedroot = DH::findFirstElementOrDie('shared', $this->configroot);
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
			$lvsys = new VirtualSystem($this);

			$lvname = DH::findAttribute('name', $node);

			if( $lvname === FALSE )
				derr('cannot find VirtualSystem name');

			if( isset($this->panorama) )
			{
				$dg = $this->panorama->findApplicableDGForVsys($this->serial , $lvname);
				if( $dg !== FALSE )
				{
					$lvsys->addressStore->panoramaDG = $dg->addressStore;
					$lvsys->serviceStore->panoramaDG = $dg->serviceStore;
				}
			}

			$lvsys->load_from_domxml($node);
			$this->virtualSystems[] = $lvsys;

            $importedInterfaces = $lvsys->importedInterfaces->interfaces();
            foreach( $importedInterfaces as &$ifName )
            {
                $resolvedIf = $this->network->findInterface($ifName);
                if( $resolvedIf !== null )
                    $resolvedIf->importedByVSYS = $lvsys;
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
		$numDecryptRules = 0;


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


		foreach($this->virtualSystems as $vsys )
		{

			$numSecRules += $vsys->securityRules->count();
			$numNatRules += $vsys->natRules->count();
			$numDecryptRules += $vsys->decryptionRules->count();

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

		}

		print "Statistics for PANConf '".$this->name."'\n";
		print "- ".$numSecRules." Security Rules\n";

		print "- ".$numNatRules." Nat Rules\n";

		print "- ".$numDecryptRules." Deryption Rules\n";

		print "- ".$this->addressStore->countAddresses()." (".$gnaddresss.") address objects. {$gnaddresssUnused} unused\n";

		print "- ".$this->addressStore->countAddressGroups()." (".$gnaddressGs.") address groups. {$gnaddressGsUnused} unused\n";

		print "- ".$this->serviceStore->countServices()." (".$gnservices.") service objects. {$gnservicesUnused} unused\n";

		print "- ".$this->serviceStore->countServiceGroups()." (".$gnserviceGs.") service groups. {$gnserviceGsUnused} unused\n";

		print "- ".$this->addressStore->countTmpAddresses()." (".$gnTmpAddresses.") temporary address objects\n";

		print "- ".$this->serviceStore->countTmpServices()." (".$gnTmpServices.") temporary service objects\n";

		//print "- ".$this->zoneStore->count()." zones\n";
		print "- ".$this->tagStore->count()." tags\n";
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

