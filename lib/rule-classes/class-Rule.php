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

class Rule
{
	
	use PathableName;
	use centralServiceStoreUser;
	use centralAddressStoreUser;
    use ObjectWithDescription;
    use XmlConvertible;
	
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
	 * @var RuleStore
	 */
	public $owner = null;

    /** @var null|string[][]  */
    protected $_targets = null;

    protected $_targetIsNegated = false;

	
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
     * For developer use only
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
    protected function load_source()
    {
        $tmp = DH::findFirstElementOrCreate('source', $this->xmlroot);
        $this->source->load_from_domxml($tmp);
    }

    /**
     * For developer use only
     */
    protected function load_destination()
    {
        $tmp = DH::findFirstElementOrCreate('destination', $this->xmlroot);
        $this->destination->load_from_domxml($tmp);
    }

    /**
     * For developer use only
     *
     */
    protected function load_common_from_domxml()
    {
        foreach($this->xmlroot->childNodes as $node)
        {
            /** @var DOMElement $node */
            if( $node->nodeType != XML_ELEMENT_NODE )
                continue;

            if( $node->nodeName == 'disabled' )
            {
                $lstate = strtolower($node->textContent);
                if( $lstate == 'yes' )
                {
                    $this->disabled = true;
                }
            }
            else if( $node->nodeName == 'tag' )
            {
                $this->tags->load_from_domxml($node);
            }
            else if( $node->nodeName == 'description' )
            {
                $this->_description = $node->textContent;
            }
            else if( $node->nodeName == 'target' )
            {
                $targetNegateNode = DH::findFirstElement('negate', $node);
                if( $targetNegateNode !== false )
                {
                    $this->_targetIsNegated = yesNoBool($targetNegateNode->textContent);
                }

                $targetDevicesNodes = DH::findFirstElement('devices', $node);

                if( $targetDevicesNodes !== false )
                {
                    foreach( $targetDevicesNodes->childNodes as $targetDevicesNode )
                    {
                        if( $targetDevicesNode->nodeType != XML_ELEMENT_NODE )
                            continue;

                        /**  @var DOMElement $targetDevicesNode */

                        $targetSerial = $targetDevicesNode->getAttribute('name');
                        if( strlen($targetSerial) < 1)
                        {
                            mwarning('a target with empty serial number was found', $targetDevicesNodes);
                            continue;
                        }

                        if( $this->_targets === null )
                            $this->_targets = Array();

                        $vsysNodes = DH::firstChildElement($targetDevicesNode);

                        if( $vsysNodes === false )
                        {
                            $this->_targets[$targetSerial] = Array();
                            //mwarning($targetSerial, $targetDevicesNode);
                        }
                        else
                        {
                            foreach($vsysNodes->childNodes as $vsysNode)
                            {
                                if( $vsysNode->nodeType != XML_ELEMENT_NODE )
                                    continue;
                                /**  @var DOMElement $vsysNode */
                                $vsysName = $vsysNode->getAttribute('name');
                                if( strlen($vsysName) < 1 )
                                    continue;

                                $this->_targets[$targetSerial][$vsysName] = $vsysName;
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * @return bool TRUE if an update was made
     */
    public function target_setAny()
    {
        if( $this->_targets === null )
            return false;

        $this->_targets = null;

        $node = DH::findFirstElement('target', $this->xmlroot);
        if( $node !== false )
        {
            $deviceNode = DH::findFirstElement('devices', $node);
            if( $deviceNode !== false )
                $node->removeChild($deviceNode);
        }

        return true;
    }

    /**
     * @return bool TRUE if an update was made
     */
    public function API_target_setAny()
    {
        $ret = $this->target_setAny();

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $con->sendDeleteRequest($this->getXPath().'/target/devices');
        }

        return $ret;
    }

    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function target_addDevice( $serialNumber, $vsys=null)
    {
        if( strlen($serialNumber) < 4 )
            derr("unsupported serial number to be added in target: '{$serialNumber}'");

        if( $vsys !== null && strlen($vsys) < 1 )
            derr("unsupported vsys value to be added in target : '{$vsys}'");

        if( $this->_targets === null )
            $this->_targets = Array();

        if( !isset($this->_targets[$serialNumber]) )
        {
            $this->_targets[$serialNumber] = Array();
            if( $vsys !== null )
                $this->_targets[$serialNumber][$vsys] = $vsys;

            $this->target_rewriteXML();
            return true;
        }

        if( count($this->_targets[$serialNumber]) == 0 )
        {
            if( $vsys === null )
                return false;

            derr("attempt to add a VSYS ({$vsys}) in target of a rule that is mentioning a firewall ({$serialNumber}) that is not multi-vsys");
        }

        if( $vsys === null )
            derr("attempt to add a non multi-vsys firewall ({$serialNumber}) in a target that is multi-vsys");

        $this->_targets[$serialNumber][$vsys] = $vsys;
        $this->target_rewriteXML();

        return true;
    }

    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function API_target_addDevice($serialNumber, $vsys)
    {
        $ret = $this->target_addDevice($serialNumber, $vsys);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $targetNode = DH::findFirstElementOrDie('target', $this->xmlroot);
            $targetString = DH::dom_to_xml($targetNode);
            $con->sendEditRequest($this->getXPath().'/target', $targetString);
        }

        return $ret;
    }


    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function target_removeDevice( $serialNumber, $vsys=null)
    {
        if( strlen($serialNumber) < 4 )
            derr("unsupported serial number to be added in target: '{$serialNumber}'");

        if( $vsys !== null && strlen($vsys) < 1 )
            derr("unsupported vsys value to be added in target : '{$vsys}'");

        if( $this->_targets === null )
            return false;

        if( !isset($this->_targets[$serialNumber]) )
            return false;

        if( count($this->_targets[$serialNumber]) == 0 )
        {
            if( $vsys === null )
            {
                unset($this->_targets[$serialNumber]);
                if( count($this->_targets) == 0 )
                    $this->_targets = null;
                $this->target_rewriteXML();
                return true;
            }

            derr("attempt to remove a VSYS ({$vsys}) in target of a rule that is mentioning a firewall ({$serialNumber}) which is not multi-vsys");
        }

        if( $vsys === null )
            derr("attempt to remove a non multi-vsys firewall ({$serialNumber}) in a target that is multi-vsys");

        if( !isset($this->_targets[$serialNumber][$vsys] ) )
            return false;

        unset($this->_targets[$serialNumber][$vsys]);

        if( count($this->_targets[$serialNumber]) == 0 )
            unset($this->_targets[$serialNumber]);

        $this->target_rewriteXML();

        return true;
    }

    /**
     * @param string $serialNumber
     * @param null|string $vsys
     * @return bool TRUE if a change was made
     */
    public function API_target_removeDevice($serialNumber, $vsys)
    {
        $ret = $this->target_removeDevice($serialNumber, $vsys);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $targetNode = DH::findFirstElementOrDie('target', $this->xmlroot);
            $targetString = DH::dom_to_xml($targetNode);
            $con->sendEditRequest($this->getXPath().'/target', $targetString);
        }

        return $ret;
    }


    public function target_rewriteXML()
    {
        $targetNode = DH::findFirstElementOrCreate('target', $this->xmlroot);

        DH::clearDomNodeChilds($targetNode);
        DH::createElement($targetNode, 'negate', boolYesNo($this->_targetIsNegated));

        if( $this->_targets === null )
            return;

        $devicesNode = DH::createElement($targetNode, 'devices');

        foreach( $this->_targets as $serial => &$vsysList )
        {
            $entryNode = DH::createElement($devicesNode, 'entry');
            $entryNode->setAttribute('name', $serial);
            if( count($vsysList) > 0 )
            {
                $vsysNode = DH::createElement($entryNode, 'vsys');
                foreach ($vsysList as $vsys)
                {
                    $vsysEntryNode = DH::createElement($vsysNode, 'entry');
                    $vsysEntryNode->setAttribute('name', $vsys);
                }
            }
        }
    }

    /**
     * @var bool $TRUEorFALSE
     * @return bool TRUE if an update was made
     */
    public function target_negateSet($TRUEorFALSE)
    {
        if( $this->_targetIsNegated === $TRUEorFALSE )
            return false;

        $this->_targetIsNegated = $TRUEorFALSE;

        $node = DH::findFirstElementOrCreate('target', $this->xmlroot);
        DH::findFirstElementOrCreate('negate', $node, boolYesNo($TRUEorFALSE));

        return true;
    }

    public function target_isNegated()
    {
        return $this->_targetIsNegated;
    }

    /**
     * @var bool $TRUEorFALSE
     * @return bool TRUE if an update was made
     */
    public function API_target_negateSet($TRUEorFALSE)
    {
        $ret = $this->target_negateSet($TRUEorFALSE);

        if( $ret )
        {
            $con = findConnectorOrDie($this);
            $con->sendSetRequest($this->getXPath().'/target', '<negate>'.boolYesNo($TRUEorFALSE).'</negate>');
        }

        return $ret;
    }



    public function targets()
    {
        return $this->_targets;
    }

    public function targets_toString()
    {
        if( !isset($this->_targets) )
            return 'any';

        $str = '';

        foreach($this->_targets as $device => $vsyslist)
        {
            if( strlen($str) > 0 )
                $str .= ',';

            if( count($vsyslist) == 0 )
                $str .= $device;
            else
            {
                $first = true;
                foreach( $vsyslist as $vsys)
                {
                    if( !$first)
                        $str .= ',';
                    $first = false;
                    $str .= $device.'/'.$vsys;
                }
            }

        }

        return $str;
    }

    public function target_isAny()
    {
        return $this->_targets === null;
    }

    /**
     * @param string $deviceSerial
     * @param string|null $vsys
     * @return bool
     */
    public function target_hasDeviceAndVsys($deviceSerial, $vsys = null)
    {
        if( $this->_targets === null )
            return false;

        if( !isset($this->_targets[$deviceSerial]) )
            return false;

        if( count($this->_targets[$deviceSerial]) == 0 && $vsys === null )
            return true;

        if( $vsys === null )
            return false;

        return isset($this->_targets[$deviceSerial][$vsys]);
    }



	/**
	* For developer use only
	*
	*/
	protected function rewriteSDisabled_XML()
	{
		if( $this->disabled )
        {
            $find = DH::findFirstElementOrCreate('disabled', $this->xmlroot);
            DH::setDomNodeText($find, 'yes');
        }
		else
        {
            $find = DH::findFirstElementOrCreate('disabled', $this->xmlroot);
            DH::setDomNodeText($find, 'no');
        }
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
		
		if( isset($this->owner) && $this->owner !== null )
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

    /**
     * @param string $newname
     */
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

    public function isAppOverrideRule()
    {
        return false;
    }

    public function isCaptivePortalRule()
    {
        return false;
    }

    public function isAuthenticationRule()
    {
        return false;
    }

    public function isPbfRule()
    {
        return false;
    }

    public function isQoSRule()
    {
        return false;
    }

    public function isDoSRule()
    {
        return false;
    }

    public function ruleNature()
    {
        return 'unknown';
    }

}




