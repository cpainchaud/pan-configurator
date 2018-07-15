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
	use PanSubHelperTrait;


    /** @var DOMElement */
	public $xmlroot;

    /** @var DOMDocument */
    public $xmldoc;

    /** @var DOMElement */
	public $sharedroot;
	public $devicesroot;
	public $localhostlocaldomain;

    /** @var string[]|DomNode */
	public $templateroot;

    /** @var string[]|DomNode */
    public $templatestackroot;

    /** @var string[]|DomNode */
    public $devicegrouproot;

    public $version = null;

	protected $managedFirewallsSerials = Array();
    public $managedFirewallsSerialsModel = Array();

    /** @var DeviceGroup[] */
	public $deviceGroups = Array();

    /** @var Template[]  */
    public $templates = Array();

    /** @var TemplateStack[]  */
    public $templatestacks = Array();

    /** @var RuleStore */
	public $securityRules;

    /** @var RuleStore */
	public $natRules;

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
    
    /** @var AddressStore */
    public $addressStore=null;

    /** @var ServiceStore */
    public $serviceStore=null;

    /** @var ZoneStore */
    public $zoneStore=null;

    /** @var PANConf[] */
    public $managedFirewalls = Array();


    /** @var PanAPIConnector|null $connector */
	public $connector = null;

    /** @var AppStore */
    public $appStore;

    /** @var TagStore */
    public $tagStore;

    public $_fakeMode = false;

    /** @var NetworkPropertiesContainer */
    public $_fakeNetworkProperties;
	
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
        $this->captivePortalRules = new RuleStore($this, 'CaptivePortalRule', true);
        $this->authenticationRules = new RuleStore($this, 'AuthenticationRule', true);
        $this->pbfRules = new RuleStore($this, 'PbfRule', true);
        $this->qosRules = new RuleStore($this, 'QoSRule', true);
        $this->dosRules = new RuleStore($this, 'DoSRule', true);

        $this->_fakeNetworkProperties = new NetworkPropertiesContainer($this);
        
        $this->dosRules->_networkStore = $this->_fakeNetworkProperties;
        $this->pbfRules->_networkStore = $this->_fakeNetworkProperties;

	}


	public function load_from_xmlstring(&$xml)
	{
		$this->xmldoc = new DOMDocument();

		if( $this->xmldoc->loadXML($xml) !== TRUE )
			derr('Invalid XML file found');

		$this->load_from_domxml($this->xmldoc);
	}

    /**
     * @param DOMElement|DOMDocument $xml
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
        {
            $this->xmldoc = $xml->ownerDocument;
            $this->xmlroot = $xml;
        }

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


		$tmp = DH::findFirstElementOrCreate('mgt-config', $this->xmlroot);

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

		if( is_object( $this->connector ) )
            $this->managedFirewallsSerialsModel = $this->connector->panorama_getConnectedFirewallsSerials();

		$this->sharedroot = DH::findFirstElementOrCreate('shared', $this->xmlroot);

		$this->devicesroot = DH::findFirstElementOrDie('devices', $this->xmlroot);

		$this->localhostroot = DH::findFirstElementByNameAttrOrDie('entry', 'localhost.localdomain',$this->devicesroot);

		$this->devicegrouproot = DH::findFirstElementOrCreate('device-group', $this->localhostroot);
        $this->templateroot = DH::findFirstElementOrCreate('template', $this->localhostroot);
        $this->templatestackroot = DH::findFirstElementOrCreate('template-stack', $this->localhostroot);

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
        // End of application extraction

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
        // End of application groups extraction


        //
        // Extracting policies
        //
        $prerulebase = DH::findFirstElement('pre-rulebase', $this->sharedroot);
        $postrulebase = DH::findFirstElement('post-rulebase', $this->sharedroot);

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
            $tmpPost = DH::findFirstElement('authentication-portal', $postrulebase);
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
        $this->dosRules->load_from_domxml($tmp, $tmpPost);//
        //
        // end of policies extraction
        //


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
        // loading templatestacks
        //
        foreach ($this->templatestackroot->childNodes as $node)
        {
            if ($node->nodeType != XML_ELEMENT_NODE) continue;

            $ldv = new TemplateStack('*tmp*', $this);
            $ldv->load_from_domxml($node);
            $this->templatestacks[] = $ldv;
            //print "TemplateStack '{$ldv->name()}' found\n";
        }
        //
        // end of Templates
        //

        //
		// loading Device Groups now
        //
        if( $this->version < 70 || $this->_fakeMode )
        {
            foreach ($this->devicegrouproot->childNodes as $node)
            {
                if ($node->nodeType != XML_ELEMENT_NODE) continue;
                //$lvname = $node->nodeName;
                //print "Device Group '$lvname' found\n";

                $ldv = new DeviceGroup($this);
                $ldv->load_from_domxml($node);
                $this->deviceGroups[] = $ldv;
            }
        }
        else
        {
            if( $this->version < 80 )
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dginfo', $this->xmlroot);
            else
                $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/devices/entry/device-group', $this->xmlroot);

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
                {
                    print "Problems could be available with the following DeviceGroup(s)\n";
                    print_r($dgLoadOrder);
                    derr('dg-meta-data seems to be corrupted, parent.child template cannot be calculated ', $dgMetaDataNode);
                }


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
                        $parentDG->_childDeviceGroups[$dgName] = $ldv;
                        $ldv->parentDeviceGroup = $parentDG;
                        $ldv->addressStore->parentCentralStore = $parentDG->addressStore;
                        $ldv->serviceStore->parentCentralStore = $parentDG->serviceStore;
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
        $gpreAppOverrideRules = $this->appOverrideRules->countPreRules();
        $gpreCPRules = $this->captivePortalRules->countPreRules();
        $gpreAuthRules = $this->authenticationRules->countPreRules();
        $gprePbfRules = $this->pbfRules->countPreRules();
        $gpreQoSRules = $this->qosRules->countPreRules();
        $gpreDoSRules = $this->dosRules->countPreRules();

		$gpostSecRules = $this->securityRules->countPostRules();
		$gpostNatRules = $this->natRules->countPostRules();
        $gpostDecryptRules = $this->decryptionRules->countPostRules();
        $gpostAppOverrideRules = $this->appOverrideRules->countPostRules();
        $gpostCPRules = $this->captivePortalRules->countPostRules();
        $gpostAuthRules = $this->authenticationRules->countPostRules();
        $gpostPbfRules = $this->pbfRules->countPostRules();
        $gpostQoSRules = $this->qosRules->countPostRules();
        $gpostDoSRules = $this->dosRules->countPostRules();

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

        $gTagCount = $this->tagStore->count();
        $gTagUnusedCount = $this->tagStore->countUnused();

		foreach( $this->deviceGroups as $cur)
		{
			$gpreSecRules += $cur->securityRules->countPreRules();
			$gpreNatRules += $cur->natRules->countPreRules();
            $gpreDecryptRules += $cur->decryptionRules->countPreRules();
            $gpreAppOverrideRules += $cur->appOverrideRules->countPreRules();
            $gpreCPRules += $cur->captivePortalRules->countPreRules();
            $gpreAuthRules += $cur->authenticationRules->countPreRules();
            $gprePbfRules += $cur->pbfRules->countPreRules();
            $gpreQoSRules += $cur->qosRules->countPreRules();
            $gpreDoSRules += $cur->dosRules->countPreRules();

			$gpostSecRules += $cur->securityRules->countPostRules();
			$gpostNatRules += $cur->natRules->countPostRules();
            $gpostDecryptRules += $cur->decryptionRules->countPostRules();
            $gpostAppOverrideRules += $cur->appOverrideRules->countPostRules();
            $gpostCPRules += $cur->captivePortalRules->countPostRules();
            $gpostAuthRules += $cur->authenticationRules->countPostRules();
            $gpostPbfRules += $cur->pbfRules->countPostRules();
            $gpostQoSRules += $cur->qosRules->countPostRules();
            $gpostDoSRules += $cur->dosRules->countPostRules();

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

            $gTagCount += $cur->tagStore->count();
            $gTagUnusedCount += $cur->tagStore->countUnused();
		}
		
		print "Statistics for PanoramaConf '".$this->name."'\n";
		print "- ".$this->securityRules->countPreRules()." (".$gpreSecRules.") pre-Sec Rules\n";
		print "- ".$this->securityRules->countPostRules()." (".$gpostSecRules.") post-Sec Rules\n";

		print "- ".$this->natRules->countPreRules()." (".$gpreNatRules.") pre-Nat Rules\n";
		print "- ".$this->natRules->countPostRules()." (".$gpostNatRules.") post-Nat Rules\n";

        print "- ".$this->qosRules->countPreRules()." (".$gpreQoSRules.") pre-QoS Rules\n";
        print "- ".$this->qosRules->countPostRules()." (".$gpostQoSRules.") post-QoS Rules\n";

        print "- ".$this->pbfRules->countPreRules()." (".$gprePbfRules.") pre-PBF Rules\n";
        print "- ".$this->pbfRules->countPostRules()." (".$gpostPbfRules.") post-PBF Rules\n";

        print "- ".$this->decryptionRules->countPreRules()." (".$gpreDecryptRules.") pre-Decryption Rules\n";
        print "- ".$this->decryptionRules->countPostRules()." (".$gpostDecryptRules.") post-Decryption Rules\n";

        print "- ".$this->appOverrideRules->countPreRules()." (".$gpreAppOverrideRules.") pre-appOverride Rules\n";
        print "- ".$this->appOverrideRules->countPostRules()." (".$gpostAppOverrideRules.") post-appOverride Rules\n";

        print "- ".$this->captivePortalRules->countPreRules()." (".$gpreCPRules.") pre-CaptivePortal Rules\n";
        print "- ".$this->captivePortalRules->countPostRules()." (".$gpostCPRules.") post-CaptivePortal Rules\n";

        print "- ".$this->authenticationRules->countPreRules()." (".$gpreAuthRules.") pre-Authentication Rules\n";
        print "- ".$this->authenticationRules->countPostRules()." (".$gpostAuthRules.") post-Authentication Rules\n";

        print "- ".$this->dosRules->countPreRules()." (".$gpreDoSRules.") pre-DoS Rules\n";
        print "- ".$this->dosRules->countPostRules()." (".$gpostDoSRules.") post-DoS Rules\n";

		print "- ".$this->addressStore->countAddresses()." (".$gnaddresss.") address objects. {$gnaddresssUnused} unused\n";

		print "- ".$this->addressStore->countAddressGroups()." (".$gnaddressGs.") address groups. {$gnaddressGsUnused} unused\n";

		print "- ".$this->serviceStore->countServices()." (".$gnservices.") service objects. {$gnservicesUnused} unused\n";

		print "- ".$this->serviceStore->countServiceGroups()." (".$gnserviceGs.") service groups. {$gnserviceGsUnused} unused\n";

		print "- ".$this->addressStore->countTmpAddresses()." (".$gnTmpAddresses.") temporary address objects\n";

		print "- ".$this->serviceStore->countTmpServices()." (".$gnTmpServices.") temporary service objects\n";

		print "- ".$this->tagStore->count()." (".$gTagCount.") tags. {$gTagUnusedCount} unused\n";

        print "- ".$this->zoneStore->count()." zones\n";
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
	* @param $config_filename string filename you want to save config in PANOS
	*/
	public function API_uploadConfig( $config_filename = 'panconfigurator-default.xml' )
	{
		print "Uploadig config to device....";

		$url = "&type=import&category=configuration&category=configuration";
		$this->connector->sendRequest($url, false, DH::dom_to_xml($this->xmlroot), $config_filename );

		print "OK!\n";
	}

	/**
	*	load all managed firewalls configs from API from running config if $fromRunning = TRUE
	*/
	public function API_loadManagedFirewallConfigs($fromRunning)
	{
		$this->managedFirewalls = Array();

        $connector = findConnectorOrDie($this);

        foreach( $this->managedFirewallsSerials as $serial )
        {
            $fw = new PANConf($this, $serial);
            $fw->panorama = $this;
            $newCon = new PanAPIConnector(  $connector->apihost,
                                            $connector->apikey,
                                            'panos-via-panorama',
                                            $serial,
                                            $connector->port);
            $fw->API_load_from_candidate($newCon);
        }

	}

	/**
	*	load all managed firewalls configs from a directory
     * @var string $fromDirectory
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
                    $fw->panorama = $this;
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
		if( $deviceSerial === null || strlen($deviceSerial) < 1 )
			derr('invalid serial provided!');
		if( $vsysName === null || strlen($vsysName) < 1 )
			derr('invalid vsys provided!');

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
     * @param string $name
     * @return DeviceGroup
	**/
	public function createDeviceGroup($name)
	{
		$newDG = new DeviceGroup($this);
		$newDG->load_from_templateXml();
		$newDG->setName($name);

        $this->deviceGroups[] = $newDG;

        if( $this->version >= 70 )
        {
            $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/max-dg-id', $this->xmlroot);
            $dgMaxID = $dgMetaDataNode->textContent;
            $dgMaxID++;
            DH::setDomNodeText($dgMetaDataNode, "{$dgMaxID}");

            $dgMetaDataNode = DH::findXPathSingleEntryOrDie('/config/readonly/dg-meta-data/dg-info', $this->xmlroot);
            $newXmlNode = DH::importXmlStringOrDie($this->xmldoc, "<entry name=\"{$name}\"><dg-id>{$dgMaxID}</dg-id></entry>");
            $dgMetaDataNode->appendChild($newXmlNode);
        }

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



