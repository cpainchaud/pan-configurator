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
     * @param $objectToAdd Address|AddressGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        foreach($this->refrules as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'AddressGroup' )
            {
                /** @var AddressGroup $ref */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->add($objectToAdd);
            }
            elseif( $refClass == 'AddressRuleContainer' )
            {
                /** @var AddressRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->addObject($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
                    if( $ref->name == 'snathosts' )
                        derr('unsupported use case in '.$ref->owner->_PANC_shortName());
                    if( $ref->name == 'source' && $ref->owner->natType() == 'static-ip'  )
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
     * @param $objectToAdd Address|AddressGroup
     * @param $displayOutput bool
     * @param $skipIfConflict bool
     * @param $outputPadding string|int
     */
    public function API_addObjectWhereIamUsed($objectToAdd, $displayOutput = false, $outputPadding = '', $skipIfConflict = false)
    {
        if( $skipIfConflict )
            derr('unsupported');

        if( !is_string($outputPadding) )
            $outputPadding = str_pad('', $outputPadding);

        foreach($this->refrules as $ref)
        {
            $refClass = get_class($ref);
            if( $refClass == 'AddressGroup' )
            {
                /** @var AddressGroup $ref */
                if( $displayOutput )
                    print $outputPadding."- adding in {$ref->_PANC_shortName()}\n";
                $ref->API_add($objectToAdd);
            }
            elseif( $refClass == 'AddressRuleContainer' )
            {
                /** @var AddressRuleContainer $ref */

                $ruleClass = get_class($ref->owner);
                if( $ruleClass == 'SecurityRule' )
                {
                    if( $displayOutput )
                        print $outputPadding."- adding in {$ref->owner->_PANC_shortName()}\n";

                    $ref->API_add($objectToAdd);
                }
                elseif( $ruleClass == 'NatRule' )
                {
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
     * @param $displayOutput bool
     * @param $apiMode bool
     * @param $actionIfLastInRule string can be delete|setany|disable
     * @param $outputPadding string|int
     */
    private function __removeWhereIamUsed($apiMode, $displayOutput = false, $outputPadding = '', $actionIfLastInRule = 'delete' )
    {
        /** @var Address|AddressGroup $this */

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
                    $ref->API_remove($this);
                else
                    $ref->remove($this);
            }
            elseif( $refClass == 'AddressRuleContainer' )
            {
                /** @var AddressRuleContainer $ref */
                if( $ref->count() <= 1 && $actionIfLastInRule == 'delete' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so deleting {$ref->_PANC_shortName()}\n";
                    if( $apiMode)
                        $ref->owner->owner->API_remove($ref->owner, true);
                    else
                        $ref->owner->owner->remove($ref->owner, true);
                }
                elseif( $ref->count() <= 1 && $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so setting ANY {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_setAny();
                    else
                        $ref->setAny();
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
                        print $outputPadding."- last member so deleting {$ref->_PANC_shortName()}\n";
                    if( $apiMode)
                        $ref->owner->API_remove($ref, true);
                    else
                        $ref->owner->remove($ref, true);
                }
                elseif( $actionIfLastInRule == 'setany' )
                {
                    if( $displayOutput )
                        print $outputPadding."- last member so setting ANY {$ref->_PANC_shortName()}\n";
                    if( $apiMode )
                        $ref->API_setService(null);
                    else
                        $ref->setService(null);
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
            else
                derr("unsupported class '{$refClass}'");
        }
    }

    /**
     * @param $displayOutput bool
     * @param $actionIfLastInRule string can be delete|setany|disable
     * @param $outputPadding string|int
     */
    public function removeWhereIamUsed($displayOutput = false, $outputPadding = '', $actionIfLastInRule = 'delete' )
    {
        $this->__removeWhereIamUsed(false, $displayOutput, $outputPadding, $actionIfLastInRule);
    }

    /**
     * @param $displayOutput bool
     * @param $actionIfLastInRule string can be delete|setany|disable
     * @param $outputPadding string|int
     */
    public function API_removeWhereIamUsed($displayOutput = false, $outputPadding = '', $actionIfLastInRule = 'delete' )
    {
        $this->__removeWhereIamUsed(true, $displayOutput, $outputPadding, $actionIfLastInRule);
    }

}