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

class RuleStore
{
	use PathableName;
    use XmlConvertible;

	/**
	 * @var Rule[]|SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]
	 */
	protected $rules = Array();


	/**
	 * @var Rule[]|SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]
	 */
	protected $postRules = Array();

    /**
     * @var VirtualSystem|DeviceGroup|PanoramaConf|PANConf
     */
	public $owner = null;
	public $name = 'temporaryname';


	/** @var string[]|DOMElement */
	public $postRulesRoot = null;


	protected $type = '**needsomethinghere**';

	protected $fastMemToIndex=null;
	protected $fastNameToIndex=null;

	protected $fastMemToIndex_forPost=null;
	protected $fastNameToIndex_forPost=null;


    protected $isPreOrPost = false;


    static private $storeNameByType = Array(

        'SecurityRule' => Array( 'name' => 'Security', 'varName' => 'securityRules', 'xpathRoot' => 'security' ),
        'NatRule' => Array( 'name' => 'NAT', 'varName' => 'natRules', 'xpathRoot' => 'nat' ),
        'DecryptionRule' => Array( 'name' => 'Decryption', 'varName' => 'decryptionRules', 'xpathRoot' => 'decryption' ),
        'AppOverrideRule' => Array( 'name' => 'AppOverride', 'varName' => 'appOverrideRules', 'xpathRoot' => 'application-override' )

    );
 
	public function RuleStore($owner, $ruleType, $isPreOrPost = false)
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
		
		foreach($this->rules as $rule)
		{
			if( $rule->SNat_Type() == 'dynamic-ip-and-port' )
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
	 * For developper use only
	 * @param DOMElement $xml
	 * @param DOMElement $xmlPost
	 */
	public function load_from_domxml($xml , $xmlPost=null)
	{
		global $PANC_DEBUG;
		
		$this->xmlroot = $xml;		
		$count = 0;
		
		foreach( $xml->childNodes as $node )
		{
			if( $node->nodeType != 1 ) continue;
            if( $node->tagName != 'entry' )
            {
                mwarning("A rule entry with tag '{$node->tagName}' was found and ignored");
                continue;
            }
			$count++;
			if( $PANC_DEBUG && $count%1000 == 0 )
				print "Parsed $count rules so far\n";
            /** @var SecurityRule|NatRule|DecryptionRule|Rule $nr */
			$nr = new $this->type($this);
			$nr->load_from_domxml($node);
			$this->rules[] = $nr;
		}

		// print $count." prerules found\n";

		if( $this->isPreOrPost )
		{
			if( $xmlPost === null )
				derr('no <post-rulebase> xml root provided !');

			$this->postRulesRoot = $xmlPost;
			$count = 0;

			foreach ($xmlPost->childNodes as $node)
			{
				if ($node->nodeType != 1) continue;
				$count++;
				if ($PANC_DEBUG && $count % 1000 == 0)
					print "Parsed $count rules so far\n";
				$nr = new $this->type($this);
				$nr->load_from_domxml($node);
				$this->postRules[] = $nr;
			}

			//print $count." postrules found\n";
		}

		$this->regen_Indexes();
	}


	/**
	 * @param Rule $rule
	 * @param bool $inPost
	 * @return bool
	 */
	public function addRule($rule, $inPost=false)
	{
		
		if( !is_object($rule) )
			derr('this function only accepts Rule class objects');

		if( $rule->owner !== null )
			derr('Trying to add a rule that has a owner already !');

		$ser = spl_object_hash($rule);

		if( $inPost !== true )
		{
			if (!isset($this->fastMemToIndex[$ser]))
			{
				$rule->owner = $this;

				$this->rules[] = $rule;
				$index = lastIndex($this->rules);
				$this->fastMemToIndex[$ser] = $index;
				$this->fastNameToIndex[$rule->name()] = $index;

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

				$this->postRules[] = $rule;
				$index = lastIndex($this->postRules);
				$this->fastMemToIndex_forPost[$ser] = $index;
				$this->fastNameToIndex_forPost[$rule->name()] = $index;

				$this->postRulesRoot->appendChild($rule->xmlroot);

				return true;
			}
			else
				derr('You cannot add a Rule that is already here :)');
		}
			
		return false;

	}


	/**
	 * @param Rule $rule
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
	 * @param Rule $rule
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
	 * @param Rule $rule
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
	 * @param Rule $rule
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
	 * @param Rule $rule
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
	 * @param Rule $rule
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

            $dgToInspect = $this->owner->childDeviceGroups;

            while( count($dgToInspect) != 0 )
            {
                $nextDgToInspect = Array();

                foreach ($this->owner->childDeviceGroups as $dg)
                {
                    if (!$dg->$varName->isRuleNameAvailable($name, false))
                        return false;

                    $nextDgToInspect = array_merge($nextDgToInspect, $dg->childDeviceGroups);
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
	 * @return string
	 */
	public function findAvailableName($base, $suffix= '')
	{
		$maxl = 31;
		$basel = strlen($base);
		$suffixl = strlen($suffix);
		$inc = 1;
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

			$inc++;
		}
	}
	
	/**
	* Only used internally when a rule is renamed to check for it unicity and accurate indexing
	* @param SecurityRule|NatRule $rule
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
     * @param SecurityRule|NatRule $rule
     * @param string $newName
     * @return SecurityRule|NatRule
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

        /** @var SecurityRule|NatRule|DecryptionRule $newRule */
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
	 * @param Rule $rule
	 * @param string $newName
	 * @return NatRule|SecurityRule
	 */
	public function API_cloneRule($rule, $newName)
	{
		$nr = $this->cloneRule($rule, $newName);

		$con = findConnectorOrDie($this);

		$xpath = $this->getXPath($rule);
		$element = $nr->getXmlText_inline();

		$con->sendSetRequest($xpath, $element);

		return $nr;
	}


	/**
	 * this function will move $ruleToBeMoved after $ruleRef.
	 * @param Rule $ruleToBeMoved
	 * @param Rule $ruleRef
	 * @param bool $rewriteXml
	 */
	public function moveRuleAfter( $ruleToBeMoved , $ruleRef, $rewriteXml=true )
	{
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
		
		$i = 0;
		$newArray = Array();

		foreach($this->rules as $rule)
		{
			if( $rule === $ruleToBeMoved )
			{
				continue;
			}
			
			$newArray[$i] = $rule;
			
			$i++;
			
			if( $rule === $ruleRef )
			{
				$newArray[$i] = $ruleToBeMoved;
				$i++;
			}
		}
		
		$this->rules = &$newArray;
		
		$this->regen_Indexes();
		
		if( $rewriteXml )
			$this->rewriteXML();
	}

	/**
	 * @param Rule $ruleToBeMoved
	 * @param Rule $ruleRef
	 * @param bool $rewritexml
	 */
	public function API_moveRuleAfter( $ruleToBeMoved , $ruleRef, $rewritexml=true )
	{
        $this->moveRuleAfter($ruleToBeMoved , $ruleRef, $rewritexml);

		$xpath = $ruleToBeMoved->getXPath();
		$con = findConnectorOrDie($this);

		$url = 'type=config&action=move&xpath='.$xpath.'&where=after&dst='.$ruleRef->name();
		$con->sendRequest($url);
	}


	/**
	 * this function will move $ruleToBeMoved before $ruleRef.
	 * @param Rule $ruleToBeMoved
	 * @param Rule $ruleRef
	 * @param bool $rewriteXml
	 */
    public function moveRuleBefore( $ruleToBeMoved , $ruleRef, $rewriteXml=true )
    {
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

        $i = 0;
        $newArray = Array();

        foreach($this->rules as $rule)
        {
            if( $rule === $ruleToBeMoved )
            {
                continue;
            }

            if( $rule === $ruleRef )
            {
                $newArray[$i] = $ruleToBeMoved;
                $i++;
            }

            $newArray[$i] = $rule;
            $i++;
        }

        $this->rules = &$newArray;

        $this->regen_Indexes();

        if( $rewriteXml )
            $this->rewriteXML();
    }

	/**
	 * @param Rule $ruleToBeMoved
	 * @param Rule $ruleRef
	 * @param bool $rewritexml
	 */
	public function API_moveRuleBefore( $ruleToBeMoved , $ruleRef, $rewritexml=true )
	{
		$this->moveRuleBefore($ruleToBeMoved , $ruleRef, $rewritexml);

		$xpath = $ruleToBeMoved->getXPath();
		$con = findConnectorOrDie($this);

		$url = 'type=config&action=move&xpath='.$xpath.'&where=before&dst='.$ruleRef->name();
		$con->sendRequest($url);
	}
	
	
	/**
	* Returns an Array with all Rules inside this store
     * @param null|string $withFilter
	* @return SecurityRule[]|NatRule[]|DecryptionRule[]|AppOverrideRule[]
	*/
	public function & rules( $withFilter=null )
	{
        $query = null;

        if( $withFilter !== null  && $withFilter != '' )
        {
            $errMesg = '';
            $query = new RQuery('rule');
            if( $query->parseFromString($withFilter, $errMsg) === false )
                derr("error while parsing query: {$errMesg}");

            $res = Array();
            foreach( $this->rules as $rule )
            {
                if( $query->matchSingleObject($rule) )
                    $res[] = $rule;
            }
            if( $this->isPreOrPost )
            {
                foreach( $this->postRules as $rule )
                {
                    if( $query->matchSingleObject($rule) )
                        $res[] = $rule;
                }
            }
            return $res;
        }

		if( !$this->isPreOrPost )
        {
            $res = $this->rules;
            return $res;
        }

        $res = array_merge($this->rules, $this->postRules);

		return $res;
	}
	
	/**
	* Counts the number of rules in this store
	*
	*/
	public function count()
	{
		return count($this->rules) + count($this->postRules);
	}
	
	
	/**
	* Displays all rules inside this store in a more less readable format :)
	*
	*/
	public function display()
	{
		foreach($this->rules as $r )
		{
			$r->display();
		}
		foreach($this->postRules as $r )
		{
			$r->display();
		}
	}
	
	/**
	* Look for a rule named $name. Return NULL if not found
     * @param string $name
	* @return Rule|SecurityRule|NatRule|DecryptionRule
	*/
	public function find($name)
	{
		if( !is_string($name) )
			derr("String was expected for rule name");
		
		if( isset( $this->fastNameToIndex[$name]) )
			return $this->rules[$this->fastNameToIndex[$name]];

		if( isset( $this->fastNameToIndex_forPost[$name]) )
			return $this->postRules[$this->fastNameToIndex_forPost[$name]];
		
		return null;
	}
	
	/**
	* Creates a new SecurityRule in this store. It will be placed at the end of the list.
	* @param String $name name of the new Rule
	 * @param bool $inPost  create it in post or pre (if applicable)
	* @return SecurityRule
	*/
	public function newSecurityRule($name, $inPost = false)
	{
		$rule = new SecurityRule($this,true);
        $rule->owner = null;

		$this->addRule($rule, $inPost);
		$rule->setName($name);		
		
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
		$rule = new NatRule($this,true);

		$this->addRule($rule, $inPost);
		$rule->setName($name);		
		
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
        $rule = new AppOverrideRule($this,true);
        $rule->owner = null;

        $this->addRule($rule, $inPostRulebase);
        $rule->setName($name);

        return $rule;
    }


    /**
     * Removes a rule from this store (must be passed an object, not string/name). Returns TRUE if found.
     * @param Rule|SecurityRule $rule
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
			unset($this->rules[$this->fastMemToIndex[$serial]]);
			unset($this->fastMemToIndex[$serial]);
			$this->xmlroot->removeChild($rule->xmlroot);
			$rule->owner = null;

			if( $deleteForever )
			{
				$rule->cleanForDestruction();
			}
		}
		elseif( $this->isPreOrPost )
		{
			if( isset($this->fastMemToIndex_forPost[$serial] ) )
			{
				$found = true;
				unset($this->fastNameToIndex_forPost[$rule->name()]);
				unset($this->postRules[$this->fastMemToIndex_forPost[$serial]]);
				unset($this->fastMemToIndex_forPost[$serial]);
				$this->postRulesRoot->removeChild($rule->xmlroot);
				$rule->owner = null;

				if( $deleteForever )
				{
					$rule->cleanForDestruction();
				}
			}
		}
		
		return $found;
	}


    /**
     * Removes a rule from this store (must be passed an object, not string/name). Returns TRUE if found.
     * @param Rule $rule
     * @return bool
     */
	public function API_remove($rule)
	{
		$xpath = $rule->getXPath();
		$ret = $this->remove($rule);

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
		DH::clearDomNodeChilds($this->xmlroot);
		foreach( $this->rules as $rule )
		{
			$this->xmlroot->appendChild($rule->xmlroot);
		}
		if( $this->isPreOrPost )
		{
			DH::clearDomNodeChilds($this->postRulesRoot);
			foreach( $this->postRules as $rule )
			{
				$this->postRulesRoot->appendChild($rule->xmlroot);
			}
		}
	}
	
	protected function regen_Indexes()
	{
		$this->fastMemToIndex = Array();
		$this->fastNameToIndex = Array();
		
		foreach($this->rules as $i=>$rule)
		{
			$this->fastMemToIndex[spl_object_hash($rule)] = $i ;
			$this->fastNameToIndex[$rule->name()] = $i ;
		}

		if( !$this->isPreOrPost )
			return;

		$this->fastMemToIndex_forPost = Array();
		$this->fastNameToIndex_forPost = Array();

		foreach($this->postRules as $i=>$rule)
		{
			$this->fastMemToIndex_forPost[spl_object_hash($rule)] = $i ;
			$this->fastNameToIndex_forPost[$rule->name()] = $i ;
		}
	}
	
	public function name()
	{
		return $this->name;
	}

	public function &getXPath(Rule $contextRule)
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
	 * @return DecryptionRule[]|AppOverrideRule[]|NatRule[]|Rule[]|SecurityRule[]
	 */
	public function preRules()
	{
		if( !$this->isPreOrPost )
			derr('This is not a panorama/devicegroup based RuleStore');

		return $this->rules;
	}


	/**
	 * @return DecryptionRule[]|AppOverrideRule[]|NatRule[]|Rule[]|SecurityRule[]
	 */
	public function postRules()
	{
		if( !$this->isPreOrPost )
			derr('This is not a panorama/devicegroup based RuleStore');

		return $this->postRules;
	}

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

	public function ruleIsPostRule(Rule $rule)
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

	public function countPreRules()
	{
		if(!$this->isPreOrPost )
			derr('unsupported');

		return count($this->rules);
	}

	public function countPostRules()
	{
		if(!$this->isPreOrPost )
			derr('unsupported');

		return count($this->postRules);
	}

    /**
     * @param $rule string|Rule|SecurityRule|NatRule|DecryptionRule
     */
    /* public function getRulePosition($rule)
    {
        if( is_string($rule) )
        {
            $rule = $this->find($rule);
            if( $rule === null )
                derr("cannot find a rule named '{$rule->name()}'");
            return $this->getRulePosition($rule);
        }
        elseif( !is_object($rule) )
            derr("unsupported object type");

        if( !$this->isPreOrPost || $this->ruleIsPreRule($rule) )
        {
            $index = $this->fastNameToIndex[$rule->name()];
            $indexToPost = $this->
        }
        elseif( $this->ruleIsPostRule($rule) )
        {
            $index = $this->fastNameToIndex_forPost[$rule->name()];
        }
        else
            derr("rule '{$rule->name()}'");

    }*/


}


