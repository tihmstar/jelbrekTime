//
//  InterfaceController.h
//  jelbrekT1m3 WatchKit Extension
//
//  Created by tihmstar on 18.07.18.
//  Copyright © 2018 tihmstar. All rights reserved.
//

#import <WatchKit/WatchKit.h>
#import <Foundation/Foundation.h>

@interface InterfaceController : WKInterfaceController
@property (unsafe_unretained, nonatomic) IBOutlet WKInterfaceLabel *statusLabel;
@property (unsafe_unretained, nonatomic) IBOutlet WKInterfaceButton *jbButton;
- (IBAction)jelbrekPressed;

@end
