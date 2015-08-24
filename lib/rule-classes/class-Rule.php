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

class Rule
{
	
	use PathableName;
    use XmlConvertible;
	use centralServiceStoreUser;
	use centralAddressStoreUser;
    use ObjectWithDescription;
	
	protected $name = 'temporaryname';
	protected $disabled = false;
	
	/**
	* @var ZoneRuleContainer
	*/
	public $from = null;
	/**
	* @var ZoneRuleContainer
	*/
	public $to = null;
	/**
	* @var AddressRuleContainer
	*/
	public $source;
	/**
	* @var AddressRuleContainer
	*/
	public $destination;

	/**
	* @var TagRuleContainer
	*/
	public $tags;

	/**
	* @var ServiceRuleContainer
	*/
	public $services;

	/**
	 * @var null|RuleStore
	 */
	public $owner = null;

    /**
     * @var null|string[]|DOMNode
     */
	protected $disabledroot = null;
	
	/**
	* Returns name of this rule
	* @return string
	*/
	public function name()
	{
		return $this->name;
	}
	
	/**
	*
	* @return bool
	*/
	public function isDisabled()
	{
		return $this->disabled;
	}
	
	/**
	*
	* @return bool
	*/
	public function isEnabled()
	{
		if ($this->disabled)
			return false;
		
		return true;
	}
	
	
	/**
	* For developper use only
	*
	*/
	protected function init_from_with_store()
	{
		$this->from = new ZoneRuleContainer($this);
		$this->from->setName('from');	
	}

    /**
     * For developper use only
     */
    protected function load_from()
    {
        $tmp = DH::findFirstElementOrCreate('from', $this->xmlroot);
        $this->from->load_from_domxml($tmp);
    }


    /**
     * For developer use only
     */
    protected function load_to()
    {
        $tmp = DH::findFirstElementOrCreate('to', $this->xmlroot);
        $this->to->load_from_domxml($tmp);
    }


    /**
     * For developer use only
     */
    protected function load_tags()
    {
        $tmp = DH::findFirstElement('tag', $this->xmlroot);
		if( $tmp !== false )
            $this->tags->load_from_domxml($tmp);
    }


    /**
     * For developper use only
     */
    protected function load_source()
    {
        $tmp = DH::findFirstElementOrCreate('source', $this->xmlroot);
        $this->source->load_from_domxml($tmp);
    }

    /**
     * For developper use only
     */
    protected function load_destination()
    {
        $tmp = DH::findFirstElementOrCreate('destination', $this->xmlroot);
        $this->destination->load_from_domxml($tmp);
    }


	
	/**
	* For developper use only
	*
	*/
	protected function init_to_with_store()
	{
		$this->to = new ZoneRuleContainer($this);
		$this->to->setName('to');
	}
	
	/**
	* For developper use only
	*
	*/
	protected function init_source_with_store()
	{
		$this->source = new AddressRuleContainer($this);
		$this->source->name = 'source';
	}
	
	/**
	* For developper use only
	*
	*/
	protected function init_destination_with_store()
	{
		$this->destination = new AddressRuleContainer($this);
		$this->destination->name = 'destination';
	}
	
	/**
	* For developper use only
	*
	*/
	protected function init_services_with_store()
	{
		$this->services = new ServiceRuleContainer($this);
		$this->services->name = 'service';
	}
	
	/**
	* For developper use only
	*
	*/
	protected function init_tags_with_store()
	{
		$this->tags = new TagRuleContainer('tag', $this);
	}
	
	/**
	* For developper use only
	*
	*/
	protected function init_apps_with_store()
	{
		$this->apps = new AppRuleContainer($this);
		$this->apps->setName('apps');
	}

	/**
	* For developper use only
	*
	*/
	protected function extract_disabled_from_domxml()
	{
		$xml = $this->xmlroot;
		
		$this->disabledroot = DH::findFirstElementOrCreate('disabled', $xml, 'no');

		//print "this rule has a <disabled>\n";
		$lstate = strtolower($this->disabledroot->textContent);
		if( $lstate == 'yes' )
		{
			//print "rule '".$this->name."' is <disabled>\n";
			$this->disabled = true;
		}
	}


	/**
	* For developper use only
	*
	*/
	protected function extract_description_from_domxml()
	{
        $this->_load_description_from_domxml();
	}
	

	/**
	* For developper use only
	*
	*/
	protected function rewriteSDisabled_XML()
	{
		if( $this->disabled )
			DH::setDomNodeText($this->disabledroot, 'yes');
		else
			DH::setDomNodeText($this->disabledroot , 'no');
	}
	
	/**
	* disable rule if $disabled = true, enable it if not
	* @param bool $disabled
	 * @return bool true if value has changed
	*/
	public function setDisabled($disabled)
	{
		$old = $this->disabled;
		$this->disabled = $disabled;
		
		if( $disabled != $old )
		{
			$this->rewriteSDisabled_XML();
			return true;
		}

		return false;
	}

	/**
	* disable rule if $disabled = true, enable it if not
	* @param bool $disabled
	 * @return bool true if value has changed
	*/
	public function API_setDisabled($disabled)
	{
		$ret = $this->setDisabled($disabled);

		if( $ret )
		{
			$xpath = $this->getXPath().'/disabled';
			$con = findConnectorOrDie($this);
			if( $this->disabled )
				$con->sendEditRequest( $xpath, '<disabled>yes</disabled>');
			else
				$con->sendEditRequest( $xpath, '<disabled>no</disabled>');
		}

		return $ret;
	}
	
	public function setEnabled($enabled)
	{
		if( $enabled )
			return $this->setDisabled(false);
		else
			return $this->setDisabled(true);
	}

	public function API_setEnabled($enabled)
	{
		if( $enabled )
			return $this->API_setDisabled(false);
		else
			return $this->API_setDisabled(true);
	}


    public function &getXPath()
    {
        $str = $this->owner->getXPath($this)."/entry[@name='".$this->name."']";

        return $str;
    }
	
	
	/**
	* return true if change was successful false if not (duplicate rulename?)
	* @return bool
	* @param string $name new name for the rule
	*/
	public function setName($name)
	{

		if( $this->name == $name )
			return true;
		
		if( isset($this->owner) )
		{
			if( $this->owner->isRuleNameAvailable($name) )
			{
				$oldname = $this->name;
				$this->name = $name;
				$this->owner->ruleWasRenamed($this,$oldname);
			}
			else
				return false;
		}
		
		$this->name = $name;

		$this->xmlroot->setAttribute('name', $name);

		return true;
		
	}

	public function API_setName($newname)
	{
		$con = findConnectorOrDie($this);
		$xpath = $this->getXPath();

		$con->sendRenameRequest($xpath, $newname);

		$this->setName($newname);	
	}


	public function isPreRule()
	{
		return $this->owner->ruleIsPreRule($this);
	}

	public function isPostRule()
	{
		return $this->owner->ruleIsPostRule($this);
	}


    public function isSecurityRule()
    {
        return false;
    }

    public function isNatRule()
    {
        return false;
    }

    public function isDecryptionRule()
    {
        return false;
    }

    public function isPbfRule()
    {
        return false;
    }

}




