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

class VirtualSystem
{
	use PathableName;
	use PanSubHelperTrait;

    /** @var AddressStore */
    public $addressStore=null;
    /** @var ServiceStore */
    public $serviceStore=null;


    /** @var TagStore|null */
	public $tagStore=null;

    /** @var AppStore|null */
    public $appStore=null;

    /** @var string */
	public $name;

    /** @var string */
    protected $_alternativeName = '';

    /** @var PANConf|null */
	public $owner = null;

	/** @var DOMElement */
	public $xmlroot;


	protected $rulebaseroot;
	
	/** @var RuleStore */
	public $securityRules;

	/** @var RuleStore */
	public $natRules;

    /** @var RuleStore */
    public $decryptionRules;

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

    /** @var ZoneStore */
    public $zoneStore=null;

    /** @var InterfaceContainer */
    public $importedInterfaces;

    /** @var DeviceGroup $parentDeviceGroup in case it load as part of Panorama */
    public $parentDeviceGroup = null;

    public $version = null;


	public function __construct(PANConf $owner, DeviceGroup $applicableDG=null)
	{
		$this->owner = $owner;

        $this->parentDeviceGroup = $applicableDG;

        $this->version = &$owner->version;
		
		$this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';

        $this->importedInterfaces = new InterfaceContainer($this, $owner->network);

		$this->appStore = $owner->appStore;

        $this->zoneStore = new ZoneStore($this);
        $this->zoneStore->setName('zoneStore');
		
		$this->serviceStore = new ServiceStore($this);
		$this->serviceStore->name = 'services';
		
		$this->addressStore = new AddressStore($this);
		$this->addressStore->name = 'addresses';

		$this->securityRules = new RuleStore($this, 'SecurityRule');
		$this->securityRules->name = 'Security';

		$this->natRules = new RuleStore($this, 'NatRule');
		$this->natRules->name = 'NAT';

        $this->decryptionRules = new RuleStore($this, 'DecryptionRule');
        $this->decryptionRules->name = 'Decryption';

        $this->appOverrideRules = new RuleStore($this, 'AppOverrideRule');
        $this->appOverrideRules->name = 'AppOverride';

        $this->captivePortalRules = new RuleStore($this, 'CaptivePortalRule');
        $this->captivePortalRules->name = 'CaptivePortal';

        $this->authenticationRules = new RuleStore($this, 'AuthenticationRule');
        $this->authenticationRules->name = 'Authentication';

        $this->pbfRules = new RuleStore($this, 'PbfRule');
        $this->pbfRules->name = 'PBF';

        $this->qosRules = new RuleStore($this, 'QoSRule');
        $this->qosRules->name = 'QoS';

        $this->dosRules = new RuleStore($this, 'DoSRule');
        $this->dosRules->name = 'DoS';

        $this->dosRules->_networkStore = $this->owner->network;
        $this->pbfRules->_networkStore = $this->owner->network;
	}



	/**
	* !! Should not be used outside of a PANConf constructor. !!
	*
	*/
	public function load_from_domxml( $xml)
	{
		$this->xmlroot = $xml;
		
		// this VSYS has a name ?
		$this->name = DH::findAttribute('name', $xml);
		if( $this->name === FALSE )
			derr("VirtualSystem name not found\n", $xml);
		
		//print "VSYS '".$this->name."' found\n";

        // this VSYS has a display-name ?
        $displayNameNode = DH::findFirstElement('display-name', $xml);
        if( $displayNameNode !== FALSE )
            $this->_alternativeName = $displayNameNode->textContent;


        //
        // loading the imported objects list
        //
        $this->importroot = DH::findFirstElementOrCreate('import', $xml);
        $networkRoot = DH::findFirstElementOrCreate('network', $this->importroot);
        $tmp = DH::findFirstElementOrCreate('interface', $networkRoot);
        $this->importedInterfaces->load_from_domxml($tmp);
        //

        if( $this->owner->owner === null )
        {

            //
            // Extract Tag objects
            //
            if ($this->owner->version >= 60)
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
            //print "VSYS '".$this->name."' address objectsloaded\n" ;
            // End of address objects extraction


            //
            // Extract address groups in this DV
            //
            $tmp = DH::findFirstElementOrCreate('address-group', $xml);
            $this->addressStore->load_addressgroups_from_domxml($tmp);
            //print "VSYS '".$this->name."' address groups loaded\n" ;
            // End of address groups extraction


            //												//
            // Extract service objects in this VSYS			//
            //												//
            $tmp = DH::findFirstElementOrCreate('service', $xml);
            $this->serviceStore->load_services_from_domxml($tmp);
            //print "VSYS '".$this->name."' service objects\n" ;
            // End of <service> extraction


            //												//
            // Extract service groups in this VSYS			//
            //												//
            $tmp = DH::findFirstElementOrCreate('service-group', $xml);
            $this->serviceStore->load_servicegroups_from_domxml($tmp);
            //print "VSYS '".$this->name."' service groups loaded\n" ;
            // End of <service-group> extraction

            //
            // Extract application
            //
            $tmp = DH::findFirstElementOrCreate('application', $xml);
            $this->appStore->load_application_custom_from_domxml($tmp);
            // End of address extraction

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
            // End of application groups groups extraction

        }

        //
        // add reference to address object, if interface IP-address is using this object
        //
        foreach( $this->importedInterfaces->interfaces() as $interface )
        {
            if( $interface->isEthernetType() && $interface->type() == "layer3" )
                $interfaces = $interface->getLayer3IPv4Addresses();
            elseif( $interface->isVlanType() || $interface->isLoopbackType() || $interface->isTunnelType() )
                $interfaces = $interface->getIPv4Addresses();
            else
                $interfaces = array();


            foreach( $interfaces as $layer3IPv4Address )
            {
                if( strpos($layer3IPv4Address, "/") === FALSE )
                {
                    $object = $this->addressStore->find($layer3IPv4Address);
                    if( is_object($object) )
                        $object->addReference($interface);
                    else
                        mwarning("interface configured objectname: " . $layer3IPv4Address . " not found.\n", $interface);
                }
            }
        }
        //Todo: addressobject reference missing for: IKE gateway / GP Portal / GP Gateway (where GP is not implemented at all)


        //
        // Extract Zone objects
        //
        $tmp = DH::findFirstElementOrCreate('zone', $xml);
        $this->zoneStore->load_from_domxml($tmp);
        // End of Zone objects extraction


        $this->rulebaseroot = DH::findFirstElement('rulebase', $xml);
        if( $this->rulebaseroot === false )
            $this->rulebaseroot = null;

        if( $this->owner->owner === null && $this->rulebaseroot !== null )
        {
            //
            // Security Rules extraction
            //
            $tmproot = DH::findFirstElement('security', $this->rulebaseroot);
            if( $tmproot !== false )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== false )
                    $this->securityRules->load_from_domxml($tmprulesroot);
            }

            //
            // Nat Rules extraction
            //
            $tmproot = DH::findFirstElement('nat', $this->rulebaseroot);
            if( $tmproot !== false )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== false )
                    $this->natRules->load_from_domxml($tmprulesroot);
            }

            //
            // Decryption Rules extraction
            //
            $tmproot = DH::findFirstElement('decryption', $this->rulebaseroot);
            if( $tmproot !== false )
            {
                $tmprulesroot = DH::findFirstElementOrCreate('rules', $tmproot);
                if( $tmprulesroot !== false )
                    $this->decryptionRules->load_from_domxml($tmprulesroot);
            }

            //
            // Decryption Rules extraction
            //
            $tmproot = DH::findFirstElement('application-override', $this->rulebaseroot);
            if( $tmproot !== false )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== false )
                    $this->appOverrideRules->load_from_domxml($tmprulesroot);
            }

            //
            // Captive Portal Rules extraction
            //
            $tmproot = DH::findFirstElement('captive-portal', $this->rulebaseroot);
            if( $tmproot !== false )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== false )
                    $this->captivePortalRules->load_from_domxml($tmprulesroot);
            }

            //
            // PBF Rules extraction
            //
            $tmproot = DH::findFirstElement('pbf', $this->rulebaseroot);
            if( $tmproot !== false )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== false )
                    $this->pbfRules->load_from_domxml($tmprulesroot);
            }

            //
            // QoS Rules extraction
            //
            $tmproot = DH::findFirstElement('qos', $this->rulebaseroot);
            if( $tmproot !== false )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== false )
                    $this->qosRules->load_from_domxml($tmprulesroot);
            }

            //
            // DoS Rules extraction
            //
            $tmproot = DH::findFirstElement('dos', $this->rulebaseroot);
            if( $tmproot !== false )
            {
                $tmprulesroot = DH::findFirstElement('rules', $tmproot);
                if( $tmprulesroot !== false )
                    $this->dosRules->load_from_domxml($tmprulesroot);
            }
        }
	}

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$this->name."']";

        return $str;
    }

	
	public function display_statistics()
	{
		print "Statistics for VSYS '".$this->name."'\n";
		print "- ".$this->securityRules->count()." security rules\n";
		print "- ".$this->natRules->count()." nat rules\n";
        print "- ".$this->qosRules->count()." qos rules\n";
        print "- ".$this->pbfRules->count()." pbf rules\n";
        print "- ".$this->decryptionRules->count()." decryption rules\n";
        print "- ".$this->appOverrideRules->count()." app-override rules\n";
        print "- ".$this->captivePortalRules->count()." capt-portal rules\n";
        print "- ".$this->dosRules->count()." dos rules\n";
        print "- {$this->addressStore->count()}/{$this->addressStore->countAddresses()}/{$this->addressStore->countAddressGroups()}/{$this->addressStore->countTmpAddresses()}/{$this->addressStore->countUnused()} total/address/group/tmp/unused objects\n";
        print "- {$this->serviceStore->count()}/{$this->serviceStore->countServices()}/{$this->serviceStore->countServiceGroups()}/{$this->serviceStore->countTmpServices()}/{$this->serviceStore->countUnused()} total/service/group/tmp/unused objects\n";
        print "- {$this->tagStore->count()} tags. {$this->tagStore->countUnused()} unused\n";

		print "- ".$this->zoneStore->count()." zones.\n";
		print "- ".$this->appStore->count()." apps.\n";
	}


	public function isVirtualSystem()
	{
		return true;
	}

    /**
     * @return string
     */
	public function name()
	{
		return $this->name;
	}


    public function setName($newName)
    {
        $this->xmlroot->setAttribute('name', $newName);
        $this->name = $newName;
    }

    /**
     * @return string
     */
    public function alternativeName()
    {
        return $this->_alternativeName;
    }

    public function setAlternativeName( $newName )
    {
        if( $newName == $this->_alternativeName )
            return false;

        if( $newName === null || strlen($newName) == 0 )
        {
            $node = DH::findFirstElement('display-name', $this->xmlroot);
            if( $node === false )
                return false;

            $this->xmlroot->removeChild($node);
            return true;
        }

        $node = DH::findFirstElementOrCreate('display-name', $this->xmlroot);
        DH::setDomNodeText($node, $newName);

        return true;
    }


    static public $templateXml = '<entry name="temporarynamechangemeplease"><address/><address-group/><service/><service-group/><rulebase></rulebase></entry>';

}
