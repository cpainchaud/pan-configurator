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

class RuleStore
{
	use PathableName;
    use XmlConvertible;

	/**
	 * @var Rule[]|SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]|CaptivePortalRule[]|PbfRule[]|QoSRule|DoSRule[]||DoSRule[]
	 */
	protected $_rules = Array();


	/**
	 * @var Rule[]|SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]|CaptivePortalRule[]|PbfRule[]|QoSRule|DoSRule[]||DoSRule[]
	 */
	protected $_postRules = Array();

    /** @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf */
	public $owner = null;
	public $name = 'temporaryname';


	/** @var string[]|DOMElement */
	public $postRulesRoot = null;


	protected $type = '**needsomethinghere**';

	protected $fastMemToIndex=null;
	protected $fastNameToIndex=null;

	protected $fastMemToIndex_forPost=null;
	protected $fastNameToIndex_forPost=null;

    /** @var NetworkPropertiesContainer|null */
    public $_networkStore = null;

    /** @var  int */
    public $version;


    protected $isPreOrPost = false;


    static private $storeNameByType = Array(

        'SecurityRule' => Array( 'name' => 'Security', 'varName' => 'securityRules', 'xpathRoot' => 'security' ),
        'NatRule' => Array( 'name' => 'NAT', 'varName' => 'natRules', 'xpathRoot' => 'nat' ),
        'DecryptionRule' => Array( 'name' => 'Decryption', 'varName' => 'decryptionRules', 'xpathRoot' => 'decryption' ),
        'AppOverrideRule' => Array( 'name' => 'AppOverride', 'varName' => 'appOverrideRules', 'xpathRoot' => 'application-override' ),
        'CaptivePortalRule' => Array( 'name' => 'CaptivePortal', 'varName' => 'captivePortalRules', 'xpathRoot' => 'captive-portal' ),
        'AuthenticationRule' => Array( 'name' => 'Authentication', 'varName' => 'authenticationRules', 'xpathRoot' => 'authentication' ),
        'PbfRule' => Array( 'name' => 'Pbf', 'varName' => 'pbfRules', 'xpathRoot' => 'pbf' ),
        'QoSRule' => Array( 'name' => 'QoS', 'varName' => 'qosRules', 'xpathRoot' => 'qos' ),
        'DoSRule' => Array( 'name' => 'DoS', 'varName' => 'dosRules', 'xpathRoot' => 'dos' )
    );
 
	public function __construct($owner, $ruleType, $isPreOrPost = false)
	{
		$this->owner = $owner;
        $this->version = &$owner->version;

		$this->isPreOrPost = $isPreOrPost;

		$allowedTypes = array_keys(self::$storeNameByType);
		if( ! in_array($ruleType, $allowedTypes) )
			derr("Error : type '$ruleType' is not a valid one");

		$this->type = $ruleType;

		$this->name = self::$storeNameByType[$this->type]['name'];
	}


	
	/**
	* Counts how many NAT rules in this Store are DIPP. If $countDisabledRules=true then it also count disabled rules
	* @param bool $countDisabledRules
     * @return bool
	*/
	public function countDyn_IP_and_Port_SNat( $countDisabledRules = false)
	{
		if( $this->type != 'NatRule' )
		{
			derr('this function cannot be called on type = "'.$this->type.'"');
		}
		
		$count = 0;
		
		foreach($this->_rules as $rule)
		{
			if( $rule->SourceNat_Type() == 'dynamic-ip-and-port' )
			{
				if( $rule->isDisabled() && $countDisabledRules ||  !$rule->isDisabled() )
				{
					$count++;
				}
			}
		}
		
		return $count;
	}



	/**
	 * For developer use only
	 * @param DOMElement|null $xml
	 * @param DOMElement|null $xmlPost
	 */
	public function load_from_domxml($xml , $xmlPost=null)
	{
		global $PANC_DEBUG;

        $duplicatesRemoval = Array();
        $nameIndex = Array();
		
		if( $xml !== null )
        {
            $this->xmlroot = $xml;

            foreach ($xml->childNodes as $node)
            {
                if ($node->nodeType != XML_ELEMENT_NODE)
                    continue;
                if ($node->tagName != 'entry')
                {
                    mwarning("A rule entry with tag '{$node->tagName}' was found and ignored");
                    continue;
                }
                /** @var SecurityRule|NatRule|DecryptionRule|Rule $nr */
                $nr = new $this->type($this);
                $nr->load_from_domxml($node);
                if( PH::$enableXmlDuplicatesDeletion )
                {
                    if( isset($nameIndex[$nr->name()]) )
                    {
                        mwarning("rule named '{$nr->name()}' is present twice on the config and was cleaned by PAN-C");
                        $duplicatesRemoval[] = $node;
                        continue;
                    }
                }

                $nameIndex[$nr->name()] = TRUE;
                $this->_rules[] = $nr;
            }
        }

		if( $this->isPreOrPost && $xmlPost !== null )
		{
			$this->postRulesRoot = $xmlPost;

			foreach ($xmlPost->childNodes as $node)
			{
				if ($node->nodeType != XML_ELEMENT_NODE)
                    continue;

                if ($node->tagName != 'entry')
                {
                    mwarning("A rule entry with tag '{$node->tagName}' was found and ignored");
                    continue;
                }
				$nr = new $this->type($this);
				$nr->load_from_domxml($node);
                if( PH::$enableXmlDuplicatesDeletion )
                {
                    if( isset($nameIndex[$nr->name()]) )
                    {
                        mwarning("rule named '{$nr->name()}' is present twice on the config and was cleaned by PAN-C");
                        $duplicatesRemoval[] = $node;
                        continue;
                    }
                }

                $nameIndex[$nr->name()] = TRUE;
                $this->_postRules[] = $nr;
			}
		}

        foreach( $duplicatesRemoval as $node )
        {
            $node->parentNode->removeChild($node);
        }

		$this->regen_Indexes();
	}


	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
	 * @param bool $inPost
	 * @return bool
	 */
	public function addRule($rule, $inPost=false)
	{
		
		if( !is_object($rule) )
			derr('this function only accepts Rule class objects');

		if( $rule->owner !== null )
			derr('Trying to add a rule that has a owner already !');

        if( $rule->owner !== $this )
        {
            $rule->from->findParentCentralStore();
            if( !$rule->isPbfRule() )
                $rule->to->findParentCentralStore();
        }

		$ser = spl_object_hash($rule);

		if( $inPost !== true )
		{
			if (!isset($this->fastMemToIndex[$ser]))
			{
				$rule->owner = $this;

				$this->_rules[] = $rule;
				$index = lastIndex($this->_rules);
				$this->fastMemToIndex[$ser] = $index;
				$this->fastNameToIndex[$rule->name()] = $index;

                if( $this->xmlroot === null )
                    $this->createXmlRoot();

				$this->xmlroot->appendChild($rule->xmlroot);

				return true;
			} else
				derr('You cannot add a Rule that is already here :)');
		}
		else
		{
			if (!isset($this->fastMemToIndex_forPost[$ser]))
			{
				$rule->owner = $this;

				$this->_postRules[] = $rule;
				$index = lastIndex($this->_postRules);
				$this->fastMemToIndex_forPost[$ser] = $index;
				$this->fastNameToIndex_forPost[$rule->name()] = $index;

                if( $this->postRulesRoot === null )
                    $this->createPostXmlRoot();

				$this->postRulesRoot->appendChild($rule->xmlroot);

				return true;
			}
			else
				derr('You cannot add a Rule that is already here :)');
		}
			
		return false;

	}


	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
	 * @param bool $inPost
	 * @return bool
	 */
	public function API_addRule( $rule, $inPost=false )
	{
		if( ! $this->addRule($rule, $inPost) )
            return false;

		$xpath = $this->getXPath($rule);
		$con = findConnectorOrDie($this);

		$con->sendSetRequest($xpath, DH::dom_to_xml($rule->xmlroot, -1, false) );

        return true;
	}

	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
	 * @return bool
	 */
	function inStore($rule)
	{
		$serial = spl_object_hash($rule);

		if( isset($this->fastMemToIndex[$serial]) )
			return true;
		if( isset($this->fastMemToIndex_forPost[$serial]) )
			return true;

		return false;
	}

	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
	 * @return bool
	 */
	public function moveRuleToPostRulebase( $rule )
	{
		if( !$this->isPreOrPost )
			derr('unsupported');

		if( ! $this->inStore($rule) )
			derr('cannot move an object that is not part of this store: '.$rule->toString() );

		$serial = spl_object_hash($rule);

		if( ! isset( $this->fastMemToIndex[$serial] ) )
			return false;

		$this->remove($rule);
		$this->addRule($rule, true);

		return true;
	}

	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
	 * @return bool
	 */
	public function API_moveRuleToPostRulebase( $rule )
	{
		if( !$this->isPreOrPost )
			derr('unsupported');

		if( ! $this->inStore($rule) )
			derr('cannot move an object that is not part of this store: '.$rule->toString() );

		$serial = spl_object_hash($rule);

		if( ! isset( $this->fastMemToIndex[$serial] ) )
			return false;

		$this->API_remove($rule);
		$this->API_addRule($rule, true);

		return true;
	}


	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
	 * @return bool
	 */
	public function moveRuleToPreRulebase( $rule )
	{
		if( !$this->isPreOrPost )
			derr('unsupported');

		if( ! $this->inStore($rule) )
			derr('cannot move an object that is not part of this store: '.$rule->toString() );

		$serial = spl_object_hash($rule);

		if( ! isset( $this->fastMemToIndex_forPost[$serial] ) )
			return false;

		$this->remove($rule);
		$this->addRule($rule, false);

		return true;
	}

	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
	 * @return bool
	 */
	public function API_moveRuleToPreRulebase( $rule )
	{
		if( !$this->isPreOrPost )
			derr('unsupported');

		if( ! $this->inStore($rule) )
			derr('cannot move an object that is not part of this store: '.$rule->toString() );

		$serial = spl_object_hash($rule);

		if( ! isset( $this->fastMemToIndex_forPost[$serial] ) )
			return false;

		$this->API_remove($rule);
		$this->API_addRule($rule, false);

		return true;
	}


	
	/**
	* Check if this name is available (for new rule for example)
	* @param string $name
     * @param bool $nested
     * @return bool
	*/
	public function isRuleNameAvailable($name, $nested=true)
	{
		if( isset($this->fastNameToIndex[$name]) )
		{
			return false;
		}
		if( $this->isPreOrPost )
		{
			if( isset($this->fastNameToIndex_forPost[$name]) )
			{
				return false;
			}
		}

		if( !$nested )
			return true;

		$ownerC = get_class($this->owner);

		if( $ownerC == 'VirtualSystem' )
		{
			// do nothing
		}
        else if( $ownerC == 'PanoramaConf' )
        {
            foreach($this->owner->deviceGroups as $dg )
            {
                $varName = $this->getStoreVarName();
                if( !$dg->$varName->isRuleNameAvailable($name, false) )
                    return false;
            }
        }
		else if( $ownerC == 'DeviceGroup' )
		{
            $varName = $this->getStoreVarName();

			if( !$this->owner->owner->$varName->isRuleNameAvailable($name, false) )
				return false;

            $dgToInspect = $this->owner->_childDeviceGroups;

            while( count($dgToInspect) != 0 )
            {
                $nextDgToInspect = Array();

                foreach ( $this->owner->_childDeviceGroups as $dg)
                {
                    if (!$dg->$varName->isRuleNameAvailable($name, false))
                        return false;

                    $nextDgToInspect = array_merge($nextDgToInspect, $dg->_childDeviceGroups);
                }

                $dgToInspect = $nextDgToInspect;
            }
		}
		else
			derr('unsupported');
		
		return true;
	}

	/**
	 * @return string
	 */
    function &getStoreVarName()
    {
        $varName = self::$storeNameByType[$this->type]['varName'];

        return $varName;
    }


	/**
	 * @param string $base
	 * @param string $suffix
	 * @param integer|string $startCount
	 * @return string
	 */
	public function findAvailableName($base, $suffix= '', $startCount = '')
	{
		$maxl = 31;
		$basel = strlen($base);
		$suffixl = strlen($suffix);
		$inc = $startCount;
		$basePlusSuffixL = $basel + $suffixl;

		while(true)
		{

			$incl = strlen(strval($inc));

			if( $basePlusSuffixL + $incl > $maxl )
			{
				$newname = substr($base,0, $basel-$suffixl-$incl).$suffix.$inc;
			}
			else
				$newname = $base.$suffix.$inc;

			if( $this->isRuleNameAvailable($newname) )
				return $newname;

			if( $startCount == '' )
				$startCount = 0;

			$inc++;
		}
	}
	
	/**
	* Only used internally when a rule is renamed to check for it unicity and accurate indexing
	* @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
	 * @param string $oldName
	*/
	public function ruleWasRenamed($rule, $oldName)
	{
        if( $rule === null )
            derr("Rule cannot be null");
		if( !$this->isRuleNameAvailable($rule->name()) )
			derr("Rule '".$rule->name()."' previously named '".$oldName."' cannot be renamed because this name is already in use");

		if( $this->isPreOrPost )
		{
			if( $rule->isPreRule() )
			{
				$this->fastNameToIndex[$rule->name()] = $this->fastNameToIndex[$oldName];
				unset($this->fastNameToIndex[$oldName]);
			}
			elseif( $rule->isPostRule() )
			{
				$this->fastNameToIndex_forPost[$rule->name()] = $this->fastNameToIndex_forPost[$oldName];
				unset($this->fastNameToIndex_forPost[$oldName]);
			}
			else
				derr('unsupported');
		}
		else
		{
			$this->fastNameToIndex[$rule->name()] = $this->fastNameToIndex[$oldName];
			unset($this->fastNameToIndex[$oldName]);
		}
	}


    /**
     * @param Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
     * @param string $newName
	 * @param null|bool $inPostRuleBase
     * @return Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule
     */
	public function cloneRule($rule, $newName = null, $inPostRuleBase=null)
	{
		if( $newName !== null )
        {
            if (!$this->isRuleNameAvailable($newName))
                derr('this rule name is not available: ' . $newName);
        }
		else
			$newName = $this->findAvailableName($rule->name(), '');

        if( $inPostRuleBase === null )
            $inPostRuleBase = $rule->isPostRule();

        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $newRule */
		$newRule = new $this->type($this);
        $xml = $rule->xmlroot->cloneNode(true);
		$newRule->load_from_domxml($xml);

        //trick to avoid name change propagation and errors
		$newRule->owner = null;

		$newRule->setName($newName);

        // finally add it to the store
		$this->addRule($newRule, $inPostRuleBase);

		return $newRule;
	}

	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
	 * @param string $newName
	 * @param $inPostRuleBase null|bool
	 * @return NatRule|SecurityRule
	 */
	public function API_cloneRule($rule, $newName, $inPostRuleBase=null)
	{
		$nr = $this->cloneRule($rule, $newName, $inPostRuleBase);

		$con = findConnectorOrDie($this);

		$xpath = $this->getXPath($rule);
		$element = $nr->getXmlText_inline();

		$con->sendSetRequest($xpath, $element);

		return $nr;
	}


	/**
	 * this function will move $ruleToBeMoved after $ruleRef.
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $ruleToBeMoved
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $ruleRef
	 * @param bool $rewriteXml
	 */
	public function moveRuleAfter( $ruleToBeMoved , $ruleRef, $rewriteXml=true )
	{
        if ($ruleToBeMoved === $ruleRef)
        {
            mwarning("Tried to move rule '{$ruleToBeMoved->name()}' after itself!");
            return;
        }

		// TODO fix after pre/post suppression
		if( is_string($ruleToBeMoved) )
		{
			$tmpRule = $this->find($ruleToBeMoved);
            if( $tmpRule === null )
                derr("cannot find rule named '$ruleToBeMoved'");
            return $this->moveRuleAfter( $tmpRule, $ruleRef, $rewriteXml );
		}

        if( is_string($ruleRef) )
        {
            $tmpRule = $this->find($ruleRef);
            if( $tmpRule === null )
                derr("cannot find rule named '$tmpRule'");
            return $this->moveRuleAfter( $ruleToBeMoved, $tmpRule, $rewriteXml );
        }

        $rtbmSerial = spl_object_hash($ruleToBeMoved);
        $refSerial = spl_object_hash($ruleRef);
        $refIsPost = false;

        if( !$this->isPreOrPost )
        {
            if (!isset($this->fastMemToIndex[$rtbmSerial]))
                derr('Cannot move a rule that is not part of this Store');

            if (!isset($this->fastMemToIndex[$refSerial]))
                derr('Cannot move after a rule that is not part of this Store');
        }
        else
        {
            $refIsPost = null;
            $moveIsPost = null;

            if( isset($this->fastMemToIndex[$rtbmSerial]) )
                $moveIsPost = false;
            elseif( isset($this->fastMemToIndex_forPost[$rtbmSerial]) )
                $moveIsPost = true;
            else
                derr("Rule '{$ruleToBeMoved->name()}' is not part of this store");

            if( isset($this->fastMemToIndex[$refSerial]) )
                $refIsPost = false;
            elseif( isset($this->fastMemToIndex_forPost[$refSerial]) )
                $refIsPost = true;
            else
                derr("Rule '{$ruleRef->name()}' is not part of this store");

            if( $refIsPost != $moveIsPost )
            {
                $this->remove($ruleToBeMoved);
                $this->addRule($ruleToBeMoved, $refIsPost);
            }
        }

        if( ! $this->isPreOrPost || ($this->isPreOrPost && !$refIsPost) )
        {
            $i = 0;
            $newArray = Array();

            foreach ($this->_rules as $rule)
            {
                if ($rule === $ruleToBeMoved)
                    continue;

                $newArray[$i] = $rule;

                $i++;

                if ($rule === $ruleRef)
                {
                    $newArray[$i] = $ruleToBeMoved;
                    $i++;
                }
            }

            $this->_rules = &$newArray;
        }
        else
        {
            $i = 0;
            $newArray = Array();
            foreach ($this->_postRules as $rule)
            {
                if ($rule === $ruleToBeMoved)
                    continue;

                $newArray[$i] = $rule;

                $i++;

                if ($rule === $ruleRef)
                {
                    $newArray[$i] = $ruleToBeMoved;
                    $i++;
                }
            }
            $this->_postRules = &$newArray;
        }
		
		$this->regen_Indexes();
		
		if( $rewriteXml )
			$this->rewriteXML();
	}

	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule $ruleToBeMoved
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule $ruleRef
	 * @param bool $rewritexml
	 */
	public function API_moveRuleAfter( $ruleToBeMoved , $ruleRef, $rewritexml=true )
	{
        if ($ruleToBeMoved === $ruleRef)
        {
            print "\n   - skip object '".PH::boldText($ruleToBeMoved->name())."' can't move after self!\n";
            return;
        }

        $this->moveRuleAfter($ruleToBeMoved , $ruleRef, $rewritexml);

		$con = findConnectorOrDie($this);

        $params = Array();

        $params['type'] = 'config';
        $params['action'] = 'move';
        $params['xpath'] = $ruleToBeMoved->getXPath();
        $params['where'] = 'after';
        $params['dst'] = $ruleRef->name();

		$con->sendRequest($params);
	}

    public function removeAll()
    {
        foreach($this->_rules as $rule)
        {
            $rule->cleanForDestruction();
            $rule->owner = null;
        }

        if( $this->xmlroot !== null )
            DH::clearDomNodeChilds($this->xmlroot);
        if( $this->postRulesRoot !== null )
            DH::clearDomNodeChilds($this->postRulesRoot);

        $this->_rules = Array();
        $this->fastMemToIndex = Array();
        $this->fastMemToIndex_forPost = Array();
        $this->fastNameToIndex = Array();
        $this->fastNameToIndex_forPost =Array();

        $this->_postRules = Array();
    }

	/**
	 * this function will move $ruleToBeMoved before $ruleRef.
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule $ruleToBeMoved
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule $ruleRef
	 * @param bool $rewriteXml
	 */
    public function moveRuleBefore( $ruleToBeMoved , $ruleRef, $rewriteXml=true )
    {
        if ($ruleToBeMoved === $ruleRef)
        {
            print "\n   - skipp object '".PH::boldText($ruleToBeMoved->name())."' can't move before self!\n";
            return;
        }

        // TODO fix after pre/post suppression
        if( is_string($ruleToBeMoved) )
        {
            $tmpRule = $this->find($ruleToBeMoved);
            if( $tmpRule === null )
                derr("cannot find rule named '$ruleToBeMoved'");
            return $this->moveRuleBefore( $tmpRule, $ruleRef, $rewriteXml );
        }

        if( is_string($ruleRef) )
        {
            $tmpRule = $this->find($ruleRef);
            if( $tmpRule === null )
                derr("cannot find rule named '$tmpRule'");
            return $this->moveRuleBefore( $ruleToBeMoved, $tmpRule, $rewriteXml );
        }

        $rtbmSerial = spl_object_hash($ruleToBeMoved);
        $refSerial = spl_object_hash($ruleRef);
        $refIsPost = false;

        if( !$this->isPreOrPost )
        {
            if (!isset($this->fastMemToIndex[$rtbmSerial]))
                derr('Cannot move a rule that is not part of this Store');

            if (!isset($this->fastMemToIndex[$refSerial]))
                derr('Cannot move after a rule that is not part of this Store');
        }
        else
        {
            $refIsPost = null;
            $moveIsPost = null;

            if( isset($this->fastMemToIndex[$rtbmSerial]) )
                $moveIsPost = false;
            elseif( isset($this->fastMemToIndex_forPost[$rtbmSerial]) )
                $moveIsPost = true;
            else
                derr("Rule '{$ruleToBeMoved->name()}' is not part of this store");

            if( isset($this->fastMemToIndex[$refSerial]) )
                $refIsPost = false;
            elseif( isset($this->fastMemToIndex_forPost[$refSerial]) )
                $refIsPost = true;
            else
                derr("Rule '{$ruleRef->name()}' is not part of this store");

            if( $refIsPost != $moveIsPost )
            {
                $this->remove($ruleToBeMoved);
                $this->addRule($ruleToBeMoved, $refIsPost);
            }
        }

        if( ! $this->isPreOrPost || ($this->isPreOrPost && !$refIsPost) )
        {
            $i = 0;
            $newArray = Array();

            foreach ($this->_rules as $rule)
            {
                if ($rule === $ruleToBeMoved)
                {
                    continue;
                }

                if ($rule === $ruleRef)
                {
                    $newArray[$i] = $ruleToBeMoved;
                    $i++;
                }

                $newArray[$i] = $rule;

                $i++;
            }

            $this->_rules = &$newArray;
        }
        else
        {
            $i = 0;
            $newArray = Array();
            foreach ($this->_postRules as $rule)
            {
                if ($rule === $ruleToBeMoved)
                {
                    continue;
                }

                if ($rule === $ruleRef)
                {
                    $newArray[$i] = $ruleToBeMoved;
                    $i++;
                }

                $newArray[$i] = $rule;

                $i++;
            }
            $this->_postRules = &$newArray;
        }

        $this->regen_Indexes();

        if( $rewriteXml )
            $this->rewriteXML();
    }

	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule $ruleToBeMoved
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule $ruleRef
	 * @param bool $rewritexml
	 */
	public function API_moveRuleBefore( $ruleToBeMoved , $ruleRef, $rewritexml=true )
	{
        if ($ruleToBeMoved === $ruleRef)
        {
            print "\n   - skipp object '".PH::boldText($ruleToBeMoved->name())."' can't move befor self!\n";
            return;
        }
		$this->moveRuleBefore($ruleToBeMoved , $ruleRef, $rewritexml);

		$con = findConnectorOrDie($this);

        $params['type'] = 'config';
        $params['action'] = 'move';
        $params['xpath'] = $ruleToBeMoved->getXPath();
        $params['where'] = 'before';
        $params['dst'] = $ruleRef->name();

        $con->sendRequest($params);
	}
	
	
	/**
	* Returns an Array with all Rules inside this store
     * @param null|string|string[] $withFilter
	* @return SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]|CaptivePortalRule[]|PbfRule[]
	*/
	public function &rules( $withFilter=null )
	{
        $query = null;

        if( $withFilter !== null  && $withFilter !== '' )
        {
			$queryContext = Array();

			if( is_array($withFilter) )
			{
				$filter = &$withFilter['query'];
				$queryContext['nestedQueries'] = &$withFilter;
			}
			else
				$filter = &$withFilter;

            $errMesg = '';
            $query = new RQuery('rule');
            if( $query->parseFromString($filter, $errMsg) === false )
                derr("error while parsing query: {$errMesg}");

            $res = Array();

			foreach($this->_rules as $rule )
			{
				$queryContext['object'] = $rule;
				if( $query->matchSingleObject($queryContext) )
					$res[] = $rule;
			}
			if( $this->isPreOrPost )
			{
				foreach($this->_postRules as $rule )
				{
					$queryContext['object'] = $rule;
					if( $query->matchSingleObject($queryContext) )
						$res[] = $rule;
				}
			}
            return $res;
        }

		if( !$this->isPreOrPost )
        {
            $res = $this->_rules;
            return $res;
        }

        $res = array_merge($this->_rules, $this->_postRules);

		return $res;
	}


    /**
     * Returns an Array with all Rules inside this store
     * @return SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]|CaptivePortalRule[]|PbfRule[]
     */
    public function &resultingRuleSet()
    {

        $res = Array();

        if( isset($this->owner->parentDeviceGroup) )
        {
            $varName = $this->getStoreVarName();
            /** @var RuleStore $var */
            $var = $this->owner->parentDeviceGroup->$varName;
            $res = $var->resultingPreRuleSet();
        }

        $res = array_merge($res, $this->_rules);

        if( $this->owner->isPanorama() || $this->owner->isDeviceGroup() )
        {
            $res = array_merge($res, $this->_postRules);
        }

        if( isset($this->owner->parentDeviceGroup) )
        {
            $varName = $this->getStoreVarName();
            /** @var RuleStore $var */
            $var = $this->owner->parentDeviceGroup->$varName;
            $res = array_merge($res, $var->resultingPostRuleSet());
        }

        return $res;
    }

    /**
     * Returns an Array with all Rules inside this store
     * @return SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]|CaptivePortalRule[]|PbfRule[]
     */
    public function &resultingPreRuleSet()
    {

        $res = Array();

        if( isset($this->owner->parentDeviceGroup) )
        {
            $varName = $this->getStoreVarName();
            /** @var RuleStore $var */
            $var = $this->owner->parentDeviceGroup->$varName;
            $res = $var->resultingPreRuleSet();
        }
        elseif( $this->owner->isPanorama() )
        {
            $varName = $this->getStoreVarName();
            /** @var RuleStore $var */
            $var = $this->owner->$varName;
            $res = $var->preRules();
        }

        $res = array_merge($res, $this->_rules);

        return $res;
    }

    /**
     * Returns an Array with all Rules inside this store
     * @return SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]|CaptivePortalRule[]|PbfRule[]
     */
    public function &resultingPostRuleSet()
    {

        $res = $this->_postRules;

        if( isset($this->owner->parentDeviceGroup) )
        {
            $varName = $this->getStoreVarName();
            /** @var RuleStore $var */
            $var = $this->owner->parentDeviceGroup->$varName;
            $res = array_merge($var->resultingPostRuleSet(), $res );
        }
        elseif( $this->owner->isPanorama() )
        {
            $varName = $this->getStoreVarName();
            /** @var RuleStore $var */
            $var = $this->owner->$varName;
            $res = array_merge($var->postRules(), $res );
        }


        return $res;
    }
	
	/**
	* Counts the number of rules in this store
	*
	*/
	public function count()
	{
		return count($this->_rules) + count($this->_postRules);
	}
	
	
	/**
	* Displays all rules inside this store in a more less readable format :)
	*
	*/
	public function display()
	{
		foreach($this->_rules as $r )
		{
			$r->display();
		}
		foreach($this->_postRules as $r )
		{
			$r->display();
		}
	}
	
	/**
	* Look for a rule named $name. Return NULL if not found
     * @param string $name
	* @return Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule
	*/
	public function find($name)
	{
		if( !is_string($name) )
			derr("String was expected for rule name");
		
		if( isset( $this->fastNameToIndex[$name]) )
			return $this->_rules[$this->fastNameToIndex[$name]];

		if( isset( $this->fastNameToIndex_forPost[$name]) )
			return $this->_postRules[$this->fastNameToIndex_forPost[$name]];
		
		return null;
	}
	
	/**
	* Creates a new SecurityRule in this store. It will be placed at the end of the list.
	* @param string $name name of the new Rule
	 * @param bool $inPost  create it in post or pre (if applicable)
	* @return SecurityRule
	*/
	public function newSecurityRule($name, $inPost = false)
	{
		$rule = new SecurityRule($this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, SecurityRule::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

		$this->addRule($rule, $inPost);
		
		return $rule;
	}

    /**
     * Creates a new SecurityRule in this store. It will be placed at the end of the list.
     * @param string $name name of the new Rule
     * @param bool $inPost  create it in post or pre (if applicable)
     * @return CaptivePortalRule
     */
    public function newCaptivePortalRule($name, $inPost = false)
    {
        $rule = new CaptivePortalRule($this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, CaptivePortalRule::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addRule($rule, $inPost);

        return $rule;
    }

	/**
	 * Creates a new NatRule in this store. It will be placed at the end of the list.
	 * @param String $name name of the new Rule
	 * @param bool $inPost  create it in post or pre (if applicable)
	 * @return NatRule
	 */
	public function newNatRule($name, $inPost = false)
	{
		$rule = new NatRule($this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, NatRule::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addRule($rule, $inPost);
		
		return $rule;
	}


    /**
     * Creates a new PBFRule in this store. It will be placed at the end of the list.
     * @param String $name name of the new Rule
     * @param bool $inPost  create it in post or pre (if applicable)
     * @return PBFRule
     */
    public function newPbfRule($name, $inPost = false)
    {
        $rule = new PbfRule($this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, PbfRule::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addRule($rule, $inPost);

        return $rule;
    }


    /**
     * Creates a new QoSRule in this store. It will be placed at the end of the list.
     * @param String $name name of the new Rule
     * @param bool $inPost  create it in post or pre (if applicable)
     * @return QoSRule
     */
    public function newQoSRule($name, $inPost = false)
    {
        $rule = new QoSRule($this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, QoSRule::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addRule($rule, $inPost);

        return $rule;
    }


    /**
     * Creates a new DoSRule in this store. It will be placed at the end of the list.
     * @param String $name name of the new Rule
     * @param bool $inPost  create it in post or pre (if applicable)
     * @return DoSRule
     */
    public function newDoSRule($name, $inPost = false)
    {
        $rule = new DoSRule($this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, DoSRule::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addRule($rule, $inPost);

        return $rule;
    }


    /**
     * Creates a new AppOverrideRule in this store. It will be placed at the end of the list.
     * @param String $name name of the new Rule
     * @param bool $inPostRulebase  create it in post or pre (if applicable)
     * @return AppOverrideRule
     */
    public function newAppOverrideRule($name, $inPostRulebase = false)
    {
        $rule = new AppOverrideRule($this);

        $xmlElement = DH::importXmlStringOrDie($this->owner->xmlroot->ownerDocument, AppOverrideRule::$templatexml);
        $rule->load_from_domxml($xmlElement);

        $rule->owner = null;
        $rule->setName($name);

        $this->addRule($rule, $inPostRulebase);

        return $rule;
    }


    /**
     * Removes a rule from this store (must be passed an object, not string/name). Returns TRUE if found.
     * @param $rule SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule
     * @param bool $deleteForever
     * @return bool
     */
	public function remove($rule, $deleteForever = false)
	{

		$found = false;
		$serial = spl_object_hash($rule);
		
		if( isset($this->fastMemToIndex[$serial] ) )
		{
			$found = true;
			unset($this->fastNameToIndex[$rule->name()]);
			unset($this->_rules[$this->fastMemToIndex[$serial]]);
			unset($this->fastMemToIndex[$serial]);
			$this->xmlroot->removeChild($rule->xmlroot);
			$rule->owner = null;

			if( $deleteForever )
				$rule->cleanForDestruction();
		}
		elseif( $this->isPreOrPost )
		{
			if( isset($this->fastMemToIndex_forPost[$serial] ) )
			{
				$found = true;
				unset($this->fastNameToIndex_forPost[$rule->name()]);
				unset($this->_postRules[$this->fastMemToIndex_forPost[$serial]]);
				unset($this->fastMemToIndex_forPost[$serial]);
				$this->postRulesRoot->removeChild($rule->xmlroot);
				$rule->owner = null;

				if( $deleteForever )
					$rule->cleanForDestruction();
			}
		}
		
		return $found;
	}


    /**
     * Removes a rule from this store (must be passed an object, not string/name). Returns TRUE if found.
     * @param $rule SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule
     * @param bool $deleteForever
     * @return bool
     */
	public function API_remove($rule, $deleteForever = false)
	{
		$xpath = $rule->getXPath();
		$ret = $this->remove($rule, $deleteForever);

		if( $ret )
		{
			$con = findConnectorOrDie($this);

			$con->sendDeleteRequest($xpath);
		}

		return $ret;
	}
	
	
	/**
	* Rewrite XML for this object, useful after a batch editing to save computing time.
	* You should not need to call it by yourself in normal situations
	*
	*/
	public function rewriteXML()
	{
        if( $this->xmlroot !== null )
            DH::clearDomNodeChilds($this->xmlroot);
        else
            $this->createXmlRoot();

		foreach($this->_rules as $rule )
		{
			$this->xmlroot->appendChild($rule->xmlroot);
		}

		if( $this->isPreOrPost )
		{
			if( $this->postRulesRoot !== null )
                DH::clearDomNodeChilds($this->postRulesRoot);
            else
                $this->createPostXmlRoot();

			foreach($this->_postRules as $rule )
			{
				$this->postRulesRoot->appendChild($rule->xmlroot);
			}
		}
	}
	
	protected function regen_Indexes()
	{
		$this->fastMemToIndex = Array();
		$this->fastNameToIndex = Array();
		
		foreach($this->_rules as $i=> $rule)
		{
			$this->fastMemToIndex[spl_object_hash($rule)] = $i ;
			$this->fastNameToIndex[$rule->name()] = $i ;
		}

		if( !$this->isPreOrPost )
			return;

		$this->fastMemToIndex_forPost = Array();
		$this->fastNameToIndex_forPost = Array();

		foreach($this->_postRules as $i=> $rule)
		{
			$this->fastMemToIndex_forPost[spl_object_hash($rule)] = $i ;
			$this->fastNameToIndex_forPost[$rule->name()] = $i ;
		}
	}

	/**
	 * @return string
	 */
	public function name()
	{
		return $this->name;
	}

	/**
	 * @param SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $contextRule
	 * @return string
	 * @throws Exception
	 */
	public function &getXPath($contextRule)
	{

			$class = get_class($this->owner);
			$serial = spl_object_hash($contextRule);

			$str = '';

			if( $class == 'VirtualSystem' )
			{
				$str = $this->owner->getXPath().'/rulebase';
			}
			else if ($class == 'DeviceGroup' )
			{
				if( $contextRule->isPreRule() )
					$str = $this->owner->getXPath().'/pre-rulebase';
				else if( $contextRule->isPostRule() )
					$str = $this->owner->getXPath().'/post-rulebase';
				else
					derr('unsupported mode');
			}
			else if ($class == 'PANConf' )
			{
                derr('unsupported');
			}
			else if ($class == 'PanoramaConf' )
			{
                if( $contextRule->isPreRule() )
					$str = "/config/shared/pre-rulebase";
                else if( $contextRule->isPostRule() )
					$str = "/config/shared/post-rulebase";
				else derr('unsupported mode');
			}
			else
				derr('unsupported mode');


            $str .= '/'.self::$storeNameByType[$this->type]['xpathRoot'].'/rules';

			return $str;
	}


	/**
	 * @return Rule[]|SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]|CaptivePortalRule[]|PbfRule[]|QoSRule|DoSRule[]||DoSRule[]
	 */
	public function preRules()
	{
		if( !$this->isPreOrPost )
			derr('This is not a panorama/devicegroup based RuleStore');

		return $this->_rules;
	}


	/**
	 * @return Rule[]|SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]|CaptivePortalRule[]|PbfRule[]|QoSRule|DoSRule[]||DoSRule[]
	 */
	public function postRules()
	{
		if( !$this->isPreOrPost )
			derr('This is not a panorama/devicegroup based RuleStore');

		return $this->_postRules;
	}

    /**
     * @param $rule
     * @return bool
     * @throws Exception
     */
	public function ruleIsPreRule(Rule $rule)
	{
		if( !$this->isPreOrPost )
			return false;

		if( $rule === null )
			derr('null value is not supported');

		$serial = spl_object_hash($rule);

		if( isset($this->fastMemToIndex[$serial]) )
			return true;

		return false;
	}

	/**
	 * @param $rule
	 * @return bool
	 * @throws Exception
	 */
	public function ruleIsPostRule($rule)
	{
		if( !$this->isPreOrPost )
			return false;

		if( $rule === null )
			derr('null value is not supported');

		$serial = spl_object_hash($rule);

		if( isset($this->fastMemToIndex_forPost[$serial]) )
			return true;

		return false;
	}

	/**
	 * @return int
	 * @throws Exception
	 */
	public function countPreRules()
	{
		if(!$this->isPreOrPost )
			derr('unsupported');

		return count($this->_rules);
	}

	/**
	 * @return int
	 * @throws Exception
	 */
	public function countPostRules()
	{
		if(!$this->isPreOrPost )
			derr('unsupported');

		return count($this->_postRules);
	}

    /**
     * @param string|Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule
     * @return int
     */
    public function getRulePosition($rule)
    {
        if( is_string($rule) )
        {
            $rule = $this->find($rule);
            /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule */
            if( $rule === null )
                derr("cannot find a rule named '{$rule->name()}'");
            return $this->getRulePosition($rule);
        }
        elseif( !is_object($rule) )
            derr("unsupported object type");

        /** @var Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule $rule */

        if( !$this->isPreOrPost || $this->ruleIsPreRule($rule) )
        {
            $count = 0;
            foreach($this->_rules as $lrule)
            {
                if( $rule === $lrule )
                    return $count;
                $count++;
            }
            derr("rule '{$rule->name()}' not found");
        }
        elseif( $this->ruleIsPostRule($rule) )
        {
            $count = 0;
            foreach($this->_postRules as $lrule)
            {
                if( $rule === $lrule )
                    return $count;
                $count++;
            }
            derr("rule '{$rule->name()}' not found");
        }
        else
            derr("rule '{$rule->name()}' not found");

    }

    /**
     * @param null|bool $lookInPreRules
     * @return null|Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule null if not found
     */
    public function getRuleOnTop($lookInPreRules = true)
    {
        if( !$this->isPreOrPost || $lookInPreRules === true )
        {
            if( count($this->_rules) == 0 )
                return null;

            return reset($this->_rules);
        }

        if( count($this->_postRules) == 0 )
            return null;

        return reset($this->_postRules);
    }

    /**
     * @param null|bool $lookInPreRules
     * @return null|Rule|SecurityRule|NatRule|DecryptionRule|AppOverrideRule|CaptivePortalRule|PbfRule|QoSRule|DoSRule null if not found
     */
    public function getRuleAtBottom($lookInPreRules = true)
    {
        if( !$this->isPreOrPost || $lookInPreRules === true )
        {
            if( count($this->_rules) == 0 )
                return null;

            return end($this->_rules);
        }

        if( count($this->_postRules) == 0 )
            return null;

        return end($this->_postRules);
    }


    public function createXmlRoot()
    {
        if( $this->xmlroot === null )
        {
            $ruleTypeForXml = self::$storeNameByType[$this->type]['xpathRoot'];
            if( $this->owner->isVirtualSystem() )
                $xml = DH::findFirstElementOrCreate('rulebase', $this->owner->xmlroot);
            else
                $xml = DH::findFirstElementOrCreate('pre-rulebase', $this->owner->xmlroot);

            $xml = DH::findFirstElementOrCreate($ruleTypeForXml, $xml);
            $this->xmlroot = DH::findFirstElementOrCreate('rules', $xml);
        }
    }

    public function createPostXmlRoot()
    {
        if( $this->postRulesRoot === null )
        {
            $ruleTypeForXml = self::$storeNameByType[$this->type]['xpathRoot'];
            $xml = DH::findFirstElementOrCreate('post-rulebase', $this->owner->xmlroot);

            $xml = DH::findFirstElementOrCreate($ruleTypeForXml, $xml);
            $this->postRulesRoot = DH::findFirstElementOrCreate('rules', $xml);
        }
    }

}


