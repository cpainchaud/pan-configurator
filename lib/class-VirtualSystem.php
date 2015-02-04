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
class VirtualSystem
{
	use PathableName;
    use centralZoneStore;
	use PanSubHelperTrait;

    /**
     * @var AddressStore
     */
    public $addressStore=null;
    /**
     * @var ServiceStore
     */
    public $serviceStore=null;


    /**
     * @var TagStore|null
     */
	public $tagStore=null;
    /**
     * @var AppStore|null
     */
    public $appStore=null;

    /**
     * @var string
     */
	public $name;

    /**
     * @var PANConf|null
     */
	public $owner = null;

	/**
	 * @var DOMElement
	 */
	public $xmlroot;


	protected $rulebaseroot;
	
	/**
	* @var RuleStore
	*/
	public $securityRules;
	/**
	* @var RuleStore
	*/
	public $natRules;
    /**
     * @var RuleStore
     */
    public $decryptionRules;

	
	
	public function VirtualSystem(PANConf $owner)
	{
		$this->owner = $owner;

        $this->version = &$owner->version;
		
		$this->tagStore = new TagStore($this);
        $this->tagStore->name = 'tags';
        $this->tagStore->setCentralStoreRole(true);


		$this->appStore = $owner->appStore;

        $this->zoneStore = new ZoneStore($this);
        $this->zoneStore->setName('zoneStore');
        $this->zoneStore->setCentralStoreRole(true);
		
		$this->serviceStore = new ServiceStore($this,true);
		$this->serviceStore->name = 'services';
		
		$this->addressStore = new AddressStore($this,true);
		$this->addressStore->name = 'addresses';
		
		$this->natRules = new RuleStore($this);
		$this->natRules->name = 'NAT';
		$this->natRules->setStoreRole(true,"NatRule");
		
		$this->securityRules = new RuleStore($this);
		$this->securityRules->name = 'Security';
		$this->securityRules->setStoreRole(true,"SecurityRule");

        $this->decryptionRules = new RuleStore($this);
        $this->decryptionRules->name = 'Decryption';
        $this->decryptionRules->setStoreRole(true,"DecryptionRule");
		
	}


    /**
     * !! Should not be used outside of a PANConf constructor. !!
     * @param array $xml
     */
	public function load_from_xml( array &$xml)
	{
		$this->xmlroot = &$xml;

        if( !isset($this->version) )
        {
            if( !isset($this->owner->version) || $this->owner->version === null  )
                derr('cannot find PANOS version from parent object');

            $this->version = $this->owner->version;
        }
		
		
		// this VSYS has a name ?
		$this->name = $xml['attributes']['name'];
		if( is_null($this->name) )
			derr("VirtualSystem name not found\n");
		
		//print "VSYS '".$this->name."' found\n";
		
		$this->rulebaseroot = &searchForName('name', 'rulebase', $xml['children']);
		if( is_null($this->rulebaseroot) )
		{
			//die("no rulebase\n");
			$this->rulebaseroot = Array('name' => 'rulebase');
			$xml['children'] = &$this->rulebaseroot;
		}
		if( !isset($this->rulebaseroot['children']) )
		{
			//die("no rulebase\n");
			$this->rulebaseroot['children'] = Array();
		}

        //
        // Extract Tags objects
        //
        if( $this->owner->version >= 60 )
        {
            $tagRoot = &searchForName('name', 'tag', $xml['children']);
            if (is_null($tagRoot))
            {
                // no object section, lets create one
                $tagRoot = Array('name' => 'tag');
                $xml['children'][] = &$tagRoot;
            }
            if (!isset($tagRoot['children']))
            {
                $tagRoot['children'] = Array();
            }
            $this->tagStore->load_from_xml($tagRoot);
        }
        // end of Tags extraction



        //
        // Extract Zones objects
        //
        $zoneRoot = &searchForName('name', 'zone', $xml['children']);
        if( is_null($zoneRoot) )
        {
            // no object section, lets create one
            $zoneRoot = Array( 'name' => 'zone' );
            $xml['children'][] = &$zoneRoot ;
        }
        if( !isset($zoneRoot['children']) )
        {
            $zoneRoot['children'] = Array();
        }

        $this->zoneStore->load_from_xml($zoneRoot);
        //print "VSYS '".$this->name."' address objectsloaded\n" ;
        // End of address objects extraction


		
		//
		// Extract address objects 
		//
		$this->addressroot = &searchForName('name', 'address', $xml['children']);
		if( is_null($this->addressroot) )
		{
			// no object section, lets create one
			$this->addressroot = Array( 'name' => 'address' );
			$xml['children'][] = &$this->addressroot ;
		}
		if( !isset($this->addressroot['children']) ) 
		{
			$this->addressroot['children'] = Array();
		}
		
		$this->addressStore->load_addresses_from_xml($this->addressroot);
		//print "VSYS '".$this->name."' address objectsloaded\n" ;
		// End of address objects extraction
		
		
		
		//
		// Extract address groups in this DV
		//
		$this->addressGsroot = &searchForName('name', 'address-group', $xml['children']);
		if( is_null($this->addressGsroot) )
		{
			// no object group section, lets create one
			$this->addressGsroot = Array( 'name' => 'address-group' );
			$xml['children'][] = &$this->addressGsroot ;
		}
		if( !isset($this->addressGsroot['children']) )
		{
			$this->addressGsroot['children'] = Array();
		}

		$this->addressStore->load_addressgroups_from_xml($this->addressGsroot);
		//print "VSYS '".$this->name."' address groups loaded\n" ;
		// End of address groups extraction
		
		
		
		//							//
		// Extract service objects in this VSYS			//
		//							//
		$this->servicesroot = &searchForName('name', 'service', $xml['children']);
		if( is_null($this->servicesroot) )
		{
			$this->servicesroot = Array('name' => 'service');
			$xml['children'][] = &$this->servicesroot;
		}
		if( !isset($this->servicesroot['children']) )
		{
			$this->servicesroot['children'] = Array();
		}
		
		$this->serviceStore->load_services_from_xml($this->servicesroot);
		//print "VSYS '".$this->name."' service objects\n" ;
		// End of <service> extraction
		
		
		
		//							//
		// Extract service groups in this VSYS			//
		//							//
		$this->serviceGsroot = &searchForName('name', 'service-group', $xml['children']);
		if( is_null($this->serviceGsroot) )
		{
			$this->serviceGsroot = Array('name' => 'service-group');
			$xml['children'][] = &$this->serviceGsroot;
		}
		if( !isset($this->serviceGsroot['children']) )
		{
			$this->serviceGsroot['children'] = Array();
		}
		$this->serviceStore->load_servicegroups_from_xml($this->serviceGsroot);
		//print "VSYS '".$this->name."' service groups loaded\n" ;
		// End of <service-group> extraction
		

		$this->extract_secrules_from_xml();
		$this->extract_natrules_from_xml();
        $this->extract_decryptrules_from_xml();
		
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

		$this->rulebaseroot = DH::findFirstElementOrCreate('rulebase', $xml);


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
        // Extract Zone objects
        //
        $tmp = DH::findFirstElementOrCreate('zone', $xml);
        $this->zoneStore->load_from_domxml($tmp);
        // End of Zone objects extraction
		
		
		//													//
		// Extract security rules objects in this VSYS		//
		//													//		
		$this->extract_secrules_from_domxml();
		// End of Security Rules extractions
		
		
		//							//
		// Extract NAT rules objects in this VSYS		//
		//							//
		$this->extract_natrules_from_domxml();
		// End of NAT Rules extractions
		
	}

    public function &getXPath()
    {
        $str = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='".$this->name."']";

        return $str;
    }

	protected function extract_secrules_from_domxml()
	{
		//print_r($this->rulebaseroot['children']);
		$tmproot = DH::findFirstElementOrCreate('security', $this->rulebaseroot );		
		$tmprulesroot = DH::findFirstElementOrCreate('rules', $tmproot);
		$this->securityRules->load_from_domxml($tmprulesroot);
		
	}
	
	protected function extract_natrules_from_xml()
	{
		
		//print_r($this->rulebaseroot['children']);
		
		$natroot = &searchForName('name', 'nat', $this->rulebaseroot['children'] );
		if( is_null($natroot) )
		{
			$natroot = Array('name' => 'nat');
			$this->rulebaseroot['children'][] = &$natroot;
		}
		if( !isset($natroot['children']) )
		{
			$natroot['children'] = Array();
		}
		
		$natrulesroot = &searchForName('name', 'rules', $natroot['children']);
		if( is_null($natrulesroot ) )
		{
			$natrulesroot = Array('name' => 'rules');
			$natroot['children'][] = &$natrulesroot;
		}
		if( !isset($natrulesroot['children']) )
		{
			$natrulesroot['children'] = Array();
		}
		
		
		$this->natRules->load_from_xml($natrulesroot);
			
	}

    protected function extract_decryptrules_from_xml()
    {

        //print_r($this->rulebaseroot['children']);

        $decryptRoot = &searchForName('name', 'decryption', $this->rulebaseroot['children'] );
        if( is_null($decryptRoot) )
        {
            $decryptRoot = Array('name' => 'decryption');
            $this->rulebaseroot['children'][] = &$decryptRoot;
        }
        if( !isset($decryptRoot['children']) )
        {
            $decryptRoot['children'] = Array();
        }

        $decryptRulesRoot = &searchForName('name', 'rules', $decryptRoot['children']);
        if( is_null($decryptRulesRoot ) )
        {
            $decryptRulesRoot = Array('name' => 'rules');
            $decryptRoot['children'][] = &$decryptRulesRoot;
        }
        if( !isset($decryptRulesRoot['children']) )
        {
            $decryptRulesRoot['children'] = Array();
        }


        $this->decryptionRules->load_from_xml($decryptRulesRoot);

    }

	protected function extract_natrules_from_domxml()
	{
		//print_r($this->rulebaseroot['children']);
		$tmproot = DH::findFirstElementOrCreate('nat', $this->rulebaseroot );		
		$tmprulesroot = DH::findFirstElementOrCreate('rules', $tmproot);
		$this->natRules->load_from_domxml($tmprulesroot);
		
	}

	
	
	protected function extract_secrules_from_xml()
	{
		//print_r($this->rulebaseroot['children']);
		$tmproot = &searchForName('name', 'security', $this->rulebaseroot['children'] );
		
		if( is_null($tmproot) )
		{
			$tmproot = Array('name' => 'security');
			$this->rulebaseroot['children'][] = &$tmproot;
		}
		if( !isset($tmproot['children']) )
		{
			$tmproot['children'] = Array();
		}
		
		$tmprulesroot = &searchForName('name', 'rules', $tmproot['children']);
		if( is_null($tmprulesroot) )
		{
			$tmprulesroot = Array('name' => 'rules');
			$natroot['children'][] = &$tmprulesroot;
		}
		if( !isset($tmprulesroot['children']) )
		{
			$tmprulesroot['children'] = Array();
		}
		
		//print_r($tmprulesroot);
		$this->securityRules->load_from_xml($tmprulesroot);
		
		
	}
	
	public function display_statistics()
	{
		print "Statistics for VSYS '".$this->name."'\n";
		print "- ".$this->securityRules->count()." security rules\n";
		print "- ".$this->natRules->count()." nat rules\n";
        print "- ".$this->decryptionRules->count()." decryption rules\n";
		print "- ".$this->addressStore->countAddresses()." address objects\n";
		print "- ".$this->addressStore->countAddressGroups()." address groups\n";
		print "- ".$this->serviceStore->countServices()." service objects\n";
		print "- ".$this->serviceStore->countServiceGroups()." service groups\n";
		print "- ".$this->addressStore->countTmpAddresses()." temporary address objects\n";
		print "- ".$this->serviceStore->countTmpServices()." temporary service objects\n";
		print "- ".$this->tagStore->count()." tags\n";
		print "- ".$this->zoneStore->count()." zones\n";
		print "- ".$this->appStore->count()." apps\n";
	}
	
	public function rewriteAllNATs_XML()
	{
        $rules = $this->natRules->rules();
		
		foreach( $rules as $rule )
        {
			$rule->rewriteSNAT_XML();
			$rule->rewriteDNAT_XML();
		}
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
	


}
