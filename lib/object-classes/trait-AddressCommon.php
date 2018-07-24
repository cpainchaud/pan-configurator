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
 * Class AddressCommon
 * @property AddressStore $owner
 */
trait AddressCommon
{
    use ReferencableObject {removeReference as super_removeReference;}

    public function isAddress()
    {
        return false;
    }

    public function isGroup()
    {
        return false;
    }

    public function isTmpAddr()
    {
        return false;
    }

    public function removeReference($ref)
    {
        $this->super_removeReference($ref);
    }

    /**
     * @param Address|AddressGroup $objectToAdd
     * @param bool $displayOutput
     * @param bool $skipIfConflict
     * @param string|int $outputPadding
     * @param bool $skipNatRules
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false, $skipNatRules = false)
    {
        /** @var Address|AddressGroup $this */
        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        if( $this === $objectToAdd )
        {
            if( $displayOutput )
                print $outputPadding."**SKIPPED** argument is same object\n";
            return;
        }

        foreach($this->refrules as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'AddressGroup' )
            {
                /** @var AddressGroup $ref */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->addMember($objectToAdd);
            }
            elseif( $refClass == 'AddressRuleContainer' )
            {
                /** @var AddressRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule'  || $ruleClass == 'DecryptionRule' || $ruleClass == 'AppOverrideRule' || $ruleClass == 'CaptivePortalRule')
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->addObject($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    if( $skipNatRules )
                    {
                        if($displayOutput)
                            print $outputPadding."- SKIPPED {$ref->owner->_PANC_shortName()} because request by user\n";
                        continue;
                    }
                    if( $ref->name == 'snathosts' )
                        derr('unsupported use case in '.$ref->owner->_PANC_shortName());
                    if( $ref->name == 'source' && $ref->owner->SourceNat_Type() == 'static-ip'  )
                        derr('unsupported use case with static-ip NAT and source insertion in '.$ref->owner->_PANC_shortName());

                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->addObject($objectToAdd);
                }
                else
                    derr('unsupported owner_class: '.$ruleClass);
            }
            else
                derr('unsupport class : '.$refClass);
        }
    }

    /**
     * @param Address|AddressGroup $objectToAdd
     * @param bool $displayOutput
     * @param bool $skipIfConflict
     * @param string|int $outputPadding
     * @param bool $skipNatRules
     */
    public function API_addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false, $skipNatRules = false)
    {
        /** @var Address|AddressGroup $this */

        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        if( $this === $objectToAdd )
        {
            if( $displayOutput )
                print $outputPadding."**SKIPPED** argument is same object\n";
            return;
        }

        foreach($this->refrules as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'AddressGroup' )
            {
                /** @var AddressGroup $ref */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->API_addMember($objectToAdd);
            }
            elseif( $refClass == 'AddressRuleContainer' )
            {
                /** @var AddressRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' || $ruleClass == 'DecryptionRule' || $ruleClass == 'AppOverrideRule' || $ruleClass == 'CaptivePortalRule' )
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->API_add($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    if( $skipNatRules )
                    {
                        if($displayOutput)
                            print $outputPadding."- SKIPPED {$ref->owner->_PANC_shortName()} because request by user\n";
                        continue;
                    }
                    if( $ref->name == 'snathosts' )
                        derr('unsupported use case in '.$ref->owner->_PANC_shortName());
                    if( $ref->name == 'source' && $ref->owner->natType() == 'static-ip'  )
                        derr('unsupported use case with static-ip NAT and source insertion in '.$ref->owner->_PANC_shortName());

                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->API_add($objectToAdd);
                }
                else
                    derr('unsupported owner_class: '.$ruleClass);
            }
            else
                derr('unsupport class : '.$refClass);
        }
    }

    /**
     * @param bool $displayOutput
     * @param bool $apiMode
     * @param string $actionIfLastInRule can be delete|setany|disable
     * @param string|int $outputPadding
     */
    private function __removeWhereIamUsed($apiMode, $displayOutput = false, $outputPadding = '', $actionIfLastInRule = 'delete' )
    {
        //Todo: address objects used at interfaces do not have a reference set

        /** @var Address|AddressGroup $this */

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        $allowedActionIfLastInRule = Array('delete' => true, 'setany' => true, 'disable' => true);
        if( !isset($allowedActionIfLastInRule[$actionIfLastInRule]) )
            derr('unsupported actionIfLastInRule='.$actionIfLastInRule);

        foreach($this->getReferences() as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'AddressGroup' )
            {
                /** @var AddressGroup $ref */
                if( $displayOutput )
                    print $outputPadding."- removing from {$ref->_PANC_shortName()}\n";
                if($apiMode)
                    $ref->API_removeMember($this);
                else
                    $ref->removeMember($this);

                if( count($ref->members() ) == 0 )
                {
                    if( $displayOutput )
                        print $outputPadding."- last addressgroup member so deleting {$ref->_PANC_shortName()}\n";
                    if($apiMode)
                        $ref->API_removeWhereIamUsed( true );
                    else
                        $ref->removeWhereIamUsed( true );

                    if($apiMode)
                        $ref->API_delete();
                    else
                        $ref->owner->remove($ref);
                }

            }
            elseif( $refClass == 'AddressRuleContainer' )
            {
                /** @var AddressRuleContainer $ref */
                if( $ref->count() <= 1 && $actionIfLastInRule == 'delete' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- last member so deleting {$ref->_PANC_shortName()}\n";

                    //if rule already deleted based no need to do it again
                    if( $ref->name() == "snathosts" )
                        $is_object = is_object($ref->owner->owner);
                    else
                        $is_object = is_object($ref->owner);

                    if( $is_object )
                    {
                        if( $apiMode )
                            $ref->owner->owner->API_remove($ref->owner, TRUE);
                        else
                            $ref->owner->owner->remove($ref->owner, TRUE);
                    }
                    else
                        print "reference already deleted\n";
                }
                elseif( $ref->count() <= 1 && $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so setting ANY {$ref->_PANC_shortName()}\n";

                    if( $ref->name() !== "snathosts" )
                    {
                        if( $ref->name() == "source" )
                        {
                            if( $displayOutput )
                                print $outputPadding."  - set source to ANY\n";
                            if( $apiMode )
                                $ref->owner->source->API_setAny();
                            else
                                $ref->owner->source->setAny();
                        }
                        if( $ref->name() == "destination" )
                        {
                            if( $displayOutput )
                                print $outputPadding."  - set destination to ANY\n";
                            if( $apiMode )
                                $ref->owner->destination->API_setAny();
                            else
                                $ref->owner->destination->setAny();
                        }
                    }
                    else
                    {
                        if( !$ref->owner->sourceNatTypeIs_None()  )
                        {
                            if( $displayOutput )
                                print $outputPadding."  - setNoSNAT\n";
                            if( $apiMode )
                                $ref->owner->API_setNoSNAT();
                            else
                                $ref->owner->setNoSNAT();
                        }
                    }


                }
                elseif( $ref->count() <= 1 && $actionIfLastInRule == 'disable' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so disabling rule {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->owner->API_setDisabled(true);
                    else
                        $ref->owner->setDisabled(true);
                }
                else
                {
                    if( $displayOutput )
                        print $outputPadding."- removing from {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_remove($this);
                    else
                        $ref->remove($this);
                }
            }
            elseif( $refClass == 'NatRule' )
            {
                /** @var NatRule $ref */
                if( $actionIfLastInRule == 'delete' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- last member so deleting {$ref->_PANC_shortName()}\n";

                    //if rule already deleted based no need to do it again
                    if( is_object($ref->owner) )
                    {
                        if( $apiMode )
                            $ref->owner->API_remove($ref, TRUE);
                        else
                            $ref->owner->remove($ref, TRUE);
                    }
                }
                elseif( $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so setting ANY {$ref->_PANC_shortName()}\n";

                    if( !$ref->sourceNatTypeIs_None()  )
                    {
                        if( $displayOutput )
                            print $outputPadding."  - setNoSNAT\n";
                        if( $apiMode )
                            $ref->API_setNoSNAT();
                        else
                            $ref->setNoSNAT();
                    }

                    if( $ref->destinationNatIsEnabled()  )
                    {
                        if( $displayOutput )
                            print $outputPadding."  - setNoDNAT\n";
                        if( $apiMode )
                            $ref->API_setNoDNAT();
                        else
                            $ref->setNoDNAT();
                    }
                }
                elseif( $actionIfLastInRule == 'disable' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so disabling rule {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_setDisabled(true);
                    else
                        $ref->setDisabled(true);
                }
                else
                {
                    derr('unsupported');
                }
            }
            elseif( $refClass == "EthernetInterface" || $refClass == "VlanInterface" || $refClass == "LoopbackInterface" || $refClass == "TunnelInterface" )
            {
                if( $actionIfLastInRule == 'delete' )
                {
                    if( $displayOutput )
                        print $outputPadding . "- last member so deleting {$ref->_PANC_shortName()}\n";

                    //Todo: delete interface? check needed
                    if( $apiMode )
                        $ref->API_removeIPv4address($this->name());
                    else
                        $ref->removeIPv4Address($this->name());
                }
                elseif( $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so setting ANY {$ref->_PANC_shortName()}\n";

                    //Todo:
                    if( $apiMode )
                        $ref->API_removeIPv4address($this->name());
                    else
                        $ref->removeIPv4Address($this->name());
                }
                elseif( $actionIfLastInRule == 'disable' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so disabling rule {$ref->_PANC_shortName()}\n";

                    //Todo: anything else, how to disable?
                    if( $apiMode )
                        $ref->API_removeIPv4address($this->name());
                    else
                        $ref->removeIPv4Address($this->name());
                }
                else
                {
                    derr('unsupported');
                }
            }
            else
                derr("unsupported class '{$refClass}'");
        }
    }

    /**
     * @param bool $displayOutput
     * @param string $actionIfLastInRule can be delete|setany|disable
     * @param string|int $outputPadding
     */
    public function removeWhereIamUsed($displayOutput = false, $outputPadding = '', $actionIfLastInRule = 'delete' )
    {
        /** @var Address|AddressGroup $this */
        $this->__removeWhereIamUsed(false, $displayOutput, $outputPadding, $actionIfLastInRule);
    }

    /**
     * @param bool $displayOutput
     * @param string $actionIfLastInRule can be delete|setany|disable
     * @param string|int $outputPadding
     */
    public function API_removeWhereIamUsed($displayOutput = false, $outputPadding = '', $actionIfLastInRule = 'delete' )
    {
        /** @var Address|AddressGroup $this */
        $this->__removeWhereIamUsed(true, $displayOutput, $outputPadding, $actionIfLastInRule);
    }


    /**
     * @param bool $displayOutput
     * @param Service|ServiceGroup $withObject
     * @param string|int $outputPadding
     */
    public function API_replaceWhereIamUsed($withObject, $displayOutput = false, $outputPadding = '')
    {
        $this->__removeWhereIamUsed(true, $withObject, $displayOutput, $outputPadding);
    }

    /**
     * @param bool $displayOutput
     * @param Service|ServiceGroup $withObject
     * @param string|int $outputPadding
     */
    public function replaceWhereIamUsed($withObject, $displayOutput = false, $outputPadding = '')
    {
        $this->__removeWhereIamUsed(false, $withObject, $displayOutput, $outputPadding);
    }


    /**
     * @param bool $displayOutput
     * @param bool $apiMode
     * @param Address|AddressGroup $withObject
     * @param string|int $outputPadding
     */
    public function __replaceWhereIamUsed($apiMode, $withObject, $displayOutput = false, $outputPadding = '')
    {
        /** @var Address|AddressGroup $this */

        if( is_numeric($outputPadding) )
            $outputPadding = str_pad(' ', $outputPadding);

        /** @var AddressGroup|AddressRuleContainer $objectRef */

        foreach( $this->refrules as $objectRef)
        {
            if( $displayOutput )
                echo $outputPadding."- replacing in {$objectRef->toString()}\n";
            if( $apiMode)
                $objectRef->API_replaceReferencedObject($this, $withObject);
            else
                $objectRef->replaceReferencedObject($this, $withObject);
        }

    }

    /**
     * looks into child DeviceGroups to see if an object with same name exists in lower levels
     * @return bool
     */
    public function hasDescendants()
    {
        $owner = $this->owner->owner;

        if( $owner->isFirewall() )
            return false;
        if( $owner->isVirtualSystem() )
            return false;

        if( $owner->isPanorama() )
            $deviceGroups = $owner->deviceGroups;
        else
            $deviceGroups = $owner->childDeviceGroups(true);

        foreach( $deviceGroups as $dg )
        {
            if( $dg->addressStore->find($this->name(), null, false) )
                return true;
        }

        return false;
    }

}