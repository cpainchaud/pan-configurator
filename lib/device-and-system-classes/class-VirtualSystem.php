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

    /** @var ZoneStore */
    public $zoneStore=null;


    /** @var string[] */
    protected $_importedInterface = Array();

	
	
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

        $this->importroot = DH::findFirstElement('import',$xml);
        if( $this->importroot !== false )
        {
            $networkRoot = DH::findFirstElement('network', $this->importroot);
            if( $networkRoot !== false )
            {
                $tmp = DH::findFirstElement('interface', $networkRoot);
                if( $tmp !== false )
                {
                    foreach( $tmp->childNodes as $node )
                    {
                        if( $node->nodeType != XML_ELEMENT_NODE )
                            continue;
                        $this->_importedInterface[] = $node->textContent;
                    }
                }
            }
        }
		
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


		//
		// Security Rules extraction
		//
		$tmproot = DH::findFirstElementOrCreate('security', $this->rulebaseroot );
		$tmprulesroot = DH::findFirstElementOrCreate('rules', $tmproot);
		$this->securityRules->load_from_domxml($tmprulesroot);

		//
		// Nat Rules extraction
		//
		$tmproot = DH::findFirstElementOrCreate('nat', $this->rulebaseroot );
		$tmprulesroot = DH::findFirstElementOrCreate('rules', $tmproot);
		$this->natRules->load_from_domxml($tmprulesroot);

		//
		// Decryption Rules extraction
		//
		$tmproot = DH::findFirstElementOrCreate('decryption', $this->rulebaseroot );
		$tmprulesroot = DH::findFirstElementOrCreate('rules', $tmproot);
		$this->decryptionRules->load_from_domxml($tmprulesroot);

		
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
        print "- ".$this->decryptionRules->count()." decryption rules\n";
		print "- ".$this->addressStore->countAddresses()." address objects\n";
		print "- ".$this->addressStore->countAddressGroups()." address groups\n";
		print "- ".$this->serviceStore->countServices()." service objects\n";
		print "- ".$this->serviceStore->countServiceGroups()." service groups\n";
		print "- ".$this->addressStore->countTmpAddresses()." temporary address objects\n";
		print "- ".$this->serviceStore->countTmpServices()." temporary service objects\n";
		print "- ".$this->tagStore->count()." tags. ".$this->tagStore->countUnused()." unused\n";
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

    /**
     * @return string[]
     */
    public function importedInterfaces()
    {
        return $this->_importedInterface;
    }

	

    static public $templateXml = '<entry name="temporarynamechangemeplease"><address/><address-group/><service/><service-group/><rulebase></rulebase></entry>';

}
